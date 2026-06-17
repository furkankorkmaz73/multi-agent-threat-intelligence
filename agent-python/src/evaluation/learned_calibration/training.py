from __future__ import annotations

import argparse
import csv
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil, floor, log2
from pathlib import Path
from random import Random
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings

SETTINGS = get_settings()

from .constants import *
from .common import *
from .optional_dependencies import _load_sklearn as _default_load_sklearn


def _load_sklearn():
    import evaluation.learned_calibration as learned_calibration

    loader = getattr(learned_calibration, "_load_sklearn", _default_load_sklearn)
    if loader is _load_sklearn:
        return _default_load_sklearn()
    return loader()


def train_learned_calibration_models(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    sklearn_bundle = _load_sklearn()
    if sklearn_bundle is None:
        return {
            "predictions": [],
            "report": _skipped_model_report(
                generated_at=generated,
                reason="scikit-learn is not installed in the current Python environment",
            ),
        }
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    predictions: list[dict[str, Any]] = []
    strategies: dict[str, Any] = {}
    for strategy in ("strategy_a", "strategy_b", "strategy_c"):
        strategy_result = _train_strategy_model(rows, label_by_cve, strategy, sklearn_bundle)
        strategies[strategy] = strategy_result["report"]
        predictions.extend(strategy_result["predictions"])
    return {
        "predictions": sorted(predictions, key=lambda row: (row["strategy"], row["cve_id"])),
        "report": {
            "generated_at": generated,
            "status": "completed",
            "model_type": "LogisticRegression",
            "random_seed": 42,
            "features": list(MODEL_FEATURE_COLUMNS),
            "leakage_guard": {
                "risk_score_used_as_feature": "risk_score" in MODEL_FEATURE_COLUMNS,
                "proxy_label_fields_used_as_features": [],
            },
            "model_registry": model_registry(sklearn_bundle),
            "strategies": strategies,
            "interpretation": _model_interpretation(strategies),
        },
    }

def render_model_summary_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Model Summary",
        "",
        "This artifact is experimental and does not change production scoring behavior.",
        f"- Status: `{report.get('status', '')}`",
        f"- Model type: `{report.get('model_type', 'skipped')}`",
        f"- Random seed: `{report.get('random_seed', 'n/a')}`",
        "",
        "| Strategy | Status | Accuracy | Balanced Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for strategy, payload in (report.get("strategies") or {}).items():
        metrics = payload.get("metrics") or {}
        lines.append(
            "| {strategy} | {status} | {accuracy} | {balanced} | {precision} | {recall} | {f1} | {roc} | {pr} |".format(
                strategy=strategy,
                status=payload.get("status", ""),
                accuracy=_format_metric(metrics.get("accuracy")),
                balanced=_format_metric(metrics.get("balanced_accuracy")),
                precision=_format_metric(metrics.get("precision")),
                recall=_format_metric(metrics.get("recall")),
                f1=_format_metric(metrics.get("f1")),
                roc=_format_metric(metrics.get("roc_auc")),
                pr=_format_metric(metrics.get("pr_auc")),
            )
        )
    lines.extend(
        [
            "",
            "The model is meaningful only when proxy labels have enough class diversity and supporting evidence coverage.",
            "",
        ]
    )
    return "\n".join(lines)

def _skipped_model_report(*, generated_at: str, reason: str) -> dict[str, Any]:
    return {
        "generated_at": generated_at,
        "status": "skipped",
        "model_type": "LogisticRegression",
        "random_seed": 42,
        "features": list(MODEL_FEATURE_COLUMNS),
        "leakage_guard": {
            "risk_score_used_as_feature": "risk_score" in MODEL_FEATURE_COLUMNS,
            "proxy_label_fields_used_as_features": [],
        },
        "model_registry": model_registry(None),
        "skip_reason": reason,
        "strategies": {
            strategy: {"status": "skipped", "skip_reason": reason}
            for strategy in ("strategy_a", "strategy_b", "strategy_c")
        },
        "alternative_models": {
            model_name: {"status": "skipped", "skip_reason": reason}
            for model_name in ("random_forest", "hist_gradient_boosting", "dummy")
        },
        "interpretation": "skipped",
    }

def _train_strategy_model(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    y = [
        _safe_int((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_binary_high_{strategy}"))
        for row in rows
    ]
    positives = sum(y)
    negatives = len(y) - positives
    if len(set(y)) < 2:
        return _skipped_strategy_result(strategy, "single-class proxy labels", positives, negatives)
    if min(positives, negatives) < 2:
        return _skipped_strategy_result(strategy, "too few examples in one class for stratified split", positives, negatives)
    x = [[_feature_value(row, feature) for feature in MODEL_FEATURE_COLUMNS] for row in rows]
    train_test_split = sklearn_bundle["train_test_split"]
    LogisticRegression = sklearn_bundle["LogisticRegression"]
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )
    model = LogisticRegression(random_state=42, max_iter=1000, class_weight="balanced")
    model.fit(x_train, y_train)
    probabilities = [float(prob[1]) for prob in model.predict_proba(x)]
    predictions = [
        {
            "cve_id": str(row.get("cve_id", "")),
            "strategy": strategy,
            "proxy_binary_high": label,
            "learned_probability": round(probability, 6),
            "learned_prediction": int(probability >= 0.5),
        }
        for row, label, probability in zip(rows, y, probabilities)
    ]
    test_probabilities = [float(prob[1]) for prob in model.predict_proba(x_test)]
    test_predictions = [int(value >= 0.5) for value in test_probabilities]
    metrics = _classification_metrics(y_test, test_predictions, test_probabilities, sklearn_bundle)
    model_reports = {
        "logistic_regression": {
            "status": "evaluated",
            "metrics": metrics,
            "random_seed": 42,
        }
    }
    model_reports.update(_train_alternative_models(x_train, x_test, y_train, y_test, sklearn_bundle))
    return {
        "predictions": predictions,
        "report": {
            "status": "limited" if min(positives, negatives) < 20 else "meaningful",
            "positive_count": positives,
            "negative_count": negatives,
            "train_class_counts": _class_counts(y_train),
            "test_class_counts": _class_counts(y_test),
            "metrics": metrics,
            "models": model_reports,
            "learned_probability_summary": _probability_summary(probabilities),
            "coefficients": {
                feature: round(float(coefficient), 6)
                for feature, coefficient in zip(MODEL_FEATURE_COLUMNS, model.coef_[0])
            },
        },
    }

def model_registry(sklearn_bundle: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    if sklearn_bundle is None:
        return {
            model_name: {"available": False, "skip_reason": "scikit-learn is not installed in the current Python environment"}
            for model_name in ("logistic_regression", "random_forest", "hist_gradient_boosting", "dummy")
        }
    return {
        "logistic_regression": {"available": "LogisticRegression" in sklearn_bundle, "random_seed": 42},
        "random_forest": {"available": "RandomForestClassifier" in sklearn_bundle, "random_seed": 42},
        "hist_gradient_boosting": {"available": "HistGradientBoostingClassifier" in sklearn_bundle, "random_seed": 42},
        "dummy": {"available": "DummyClassifier" in sklearn_bundle, "random_seed": 42},
    }

def _train_alternative_models(
    x_train: Sequence[Sequence[float]],
    x_test: Sequence[Sequence[float]],
    y_train: Sequence[int],
    y_test: Sequence[int],
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    model_specs = {
        "random_forest": ("RandomForestClassifier", {"random_state": 42, "n_estimators": 100, "class_weight": "balanced"}),
        "hist_gradient_boosting": ("HistGradientBoostingClassifier", {"random_state": 42}),
        "dummy": ("DummyClassifier", {"strategy": "most_frequent", "random_state": 42}),
    }
    reports: dict[str, Any] = {}
    for model_name, (class_name, kwargs) in model_specs.items():
        model_class = sklearn_bundle.get(class_name)
        if model_class is None:
            reports[model_name] = {"status": "skipped", "skip_reason": f"{class_name} is unavailable"}
            continue
        model = model_class(**kwargs)
        model.fit(x_train, y_train)
        if hasattr(model, "predict_proba"):
            probabilities = [float(prob[1]) for prob in model.predict_proba(x_test)]
        else:
            probabilities = [float(value) for value in model.predict(x_test)]
        predictions = [int(value >= 0.5) for value in probabilities]
        reports[model_name] = {
            "status": "evaluated",
            "metrics": _classification_metrics(y_test, predictions, probabilities, sklearn_bundle),
            "random_seed": 42,
        }
    return reports

def _classification_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    probabilities: Sequence[float],
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    metrics = sklearn_bundle["metrics"]
    result = {
        "accuracy": round(float(metrics.accuracy_score(y_true, y_pred)), 4),
        "balanced_accuracy": round(float(metrics.balanced_accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(metrics.precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(metrics.recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(metrics.f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion_matrix": metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }
    if len(set(y_true)) > 1:
        result["roc_auc"] = round(float(metrics.roc_auc_score(y_true, probabilities)), 4)
        result["pr_auc"] = round(float(metrics.average_precision_score(y_true, probabilities)), 4)
    else:
        result["roc_auc"] = None
        result["pr_auc"] = None
    return result

def _skipped_strategy_result(strategy: str, reason: str, positives: int, negatives: int) -> dict[str, Any]:
    return {
        "predictions": [],
        "report": {
            "status": "skipped",
            "skip_reason": reason,
            "positive_count": positives,
            "negative_count": negatives,
            "metrics": {},
        },
    }

def _feature_value(row: Mapping[str, Any], feature: str) -> float:
    if feature == "intrinsic_criticality_floor_applied":
        return 1.0 if _truthy(row.get(feature)) else 0.0
    return _safe_float(row.get(feature))

def _class_counts(labels: Sequence[int]) -> dict[str, int]:
    return {"0": sum(1 for label in labels if label == 0), "1": sum(1 for label in labels if label == 1)}

def _probability_summary(probabilities: Sequence[float]) -> dict[str, float]:
    if not probabilities:
        return {"min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "min": round(min(probabilities), 6),
        "max": round(max(probabilities), 6),
        "mean": round(mean(probabilities), 6),
    }

def _model_interpretation(strategies: Mapping[str, Mapping[str, Any]]) -> str:
    statuses = {payload.get("status") for payload in strategies.values()}
    if statuses == {"skipped"}:
        return "skipped"
    if "meaningful" in statuses:
        return "meaningful"
    return "limited"

