from __future__ import annotations

from typing import Any, Dict, Iterable, List

import numpy as np
import pandas as pd


def build_refinement_feature_frame(rows: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(list(rows))
    if df.empty:
        return df

    defaults = {
        "cvss_score": 0.0,
        "base_cvss_component": 0.0,
        "recentness_bonus": 0.0,
        "urlhaus_correlation_bonus": 0.0,
        "dread_correlation_bonus": 0.0,
        "graph_bonus": 0.0,
        "risk_score": 0.0,
        "confidence": 0.0,
        "related_urlhaus_count": 0,
        "related_dread_count": 0,
        "centrality_score": 0.0,
        "avg_edge_confidence": 0.0,
        "age_days": 0,
        "relation_count": 0,
        "urlhaus_avg_semantic_score": 0.0,
        "dread_avg_semantic_score": 0.0,
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
            continue
        series = df[column]
        if pd.api.types.is_numeric_dtype(series):
            df[column] = pd.to_numeric(series, errors="coerce").fillna(default)
        else:
            df[column] = series.where(series.notna(), default)

    df["correlation_count"] = df["related_urlhaus_count"].astype(int) + df["related_dread_count"].astype(int)
    df["source_diversity_score"] = (df["related_urlhaus_count"].astype(int) > 0).astype(int) + (df["related_dread_count"].astype(int) > 0).astype(int)
    df["graph_support_ratio"] = (df["graph_bonus"].astype(float) / df["risk_score"].replace(0, 1)).round(4)
    df["freshness_signal"] = (1 / (1 + df["age_days"].astype(float).clip(lower=0))).round(6)
    df["semantic_signal"] = df[["urlhaus_avg_semantic_score", "dread_avg_semantic_score"]].max(axis=1).round(4)
    # Use a quantile-style proxy so the preview model is not degenerate when all records receive support.
    risk_threshold = float(df["risk_score"].quantile(0.8)) if len(df) else 0.0
    confidence_threshold = float(df["confidence"].quantile(0.7)) if len(df) else 0.0
    semantic_threshold = max(float(df["semantic_signal"].quantile(0.7)) if len(df) else 0.0, 0.05)
    df["proxy_high_risk_label"] = (
        (df["risk_score"].astype(float) >= risk_threshold)
        | ((df["graph_bonus"].astype(float) >= 0.25) & (df["confidence"].astype(float) >= confidence_threshold))
        | ((df["correlation_count"].astype(int) >= 2) & (df["semantic_signal"].astype(float) >= semantic_threshold))
    ).astype(int)
    return df


FEATURE_COLUMNS = [
    "cvss_score",
    "base_cvss_component",
    "recentness_bonus",
    "urlhaus_correlation_bonus",
    "dread_correlation_bonus",
    "graph_bonus",
    "confidence",
    "related_urlhaus_count",
    "related_dread_count",
    "centrality_score",
    "avg_edge_confidence",
    "age_days",
    "relation_count",
    "correlation_count",
    "source_diversity_score",
    "graph_support_ratio",
    "freshness_signal",
    "semantic_signal",
]


def _fit_lightweight_logistic(df: pd.DataFrame) -> Dict[str, Any]:
    work = build_refinement_feature_frame(df.to_dict(orient="records"))
    if work.empty:
        return {"coefficients": {}, "intercept": 0.0, "iterations": 0, "feature_importance": []}

    x = work[FEATURE_COLUMNS].astype(float).to_numpy()
    y = work["proxy_high_risk_label"].astype(float).to_numpy()
    means = x.mean(axis=0)
    stds = x.std(axis=0)
    stds[stds == 0] = 1.0
    x_norm = (x - means) / stds

    weights = np.zeros(x_norm.shape[1], dtype=float)
    bias = 0.0
    lr = 0.08
    iterations = 220
    n = max(len(x_norm), 1)

    for _ in range(iterations):
        logits = x_norm @ weights + bias
        probs = 1.0 / (1.0 + np.exp(-np.clip(logits, -20, 20)))
        error = probs - y
        weights -= lr * ((x_norm.T @ error) / n)
        bias -= lr * float(error.mean())

    coefficients = {name: round(float(value), 4) for name, value in zip(FEATURE_COLUMNS, weights)}
    feature_importance = [
        {"feature": name, "coefficient": round(float(value), 4), "abs_coefficient": round(abs(float(value)), 4)}
        for name, value in sorted(zip(FEATURE_COLUMNS, weights), key=lambda kv: abs(float(kv[1])), reverse=True)
    ]
    return {
        "coefficients": coefficients,
        "feature_importance": feature_importance,
        "intercept": round(float(bias), 4),
        "means": {name: round(float(value), 6) for name, value in zip(FEATURE_COLUMNS, means)},
        "stds": {name: round(float(value), 6) for name, value in zip(FEATURE_COLUMNS, stds)},
        "iterations": iterations,
    }


def summarize_refinement_model(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    frame = build_refinement_feature_frame(rows)
    model = _fit_lightweight_logistic(frame)
    if frame.empty:
        return {"record_count": 0, "positive_rate": 0.0, "feature_importance": []}
    positive_rate = float(frame["proxy_high_risk_label"].mean()) if len(frame) else 0.0
    if positive_rate in {0.0, 1.0}:
        return {
            "record_count": int(len(frame)),
            "positive_rate": round(positive_rate, 4),
            "iterations": 0,
            "intercept": 0.0,
            "feature_importance": [],
            "status": "degenerate_labels",
        }
    return {
        "record_count": int(len(frame)),
        "positive_rate": round(positive_rate, 4),
        "iterations": int(model.get("iterations", 0)),
        "intercept": float(model.get("intercept", 0.0)),
        "feature_importance": model.get("feature_importance", [])[:10],
    }


def apply_refinement_delta(row: Dict[str, Any], model: Dict[str, Any] | None = None) -> float:
    if model is None or not model.get("coefficients"):
        graph_bonus = float(row.get("graph_bonus") or 0.0)
        urlhaus_bonus = float(row.get("urlhaus_correlation_bonus") or 0.0)
        dread_bonus = float(row.get("dread_correlation_bonus") or 0.0)
        centrality = float(row.get("centrality_score") or 0.0)
        confidence = float(row.get("confidence") or 0.0)
        semantic = max(float(row.get("urlhaus_avg_semantic_score") or 0.0), float(row.get("dread_avg_semantic_score") or 0.0))
        age_days = float(row.get("age_days") or 0.0)
        delta = 0.0
        delta += min(graph_bonus * 0.12, 0.18)
        delta += min((urlhaus_bonus + dread_bonus) * 0.06, 0.16)
        delta += min(centrality * 0.22, 0.14)
        delta += min(confidence * 0.10, 0.08)
        delta += min(semantic * 0.25, 0.12)
        if age_days > 180:
            delta -= 0.10
        return round(delta, 3)

    means = model.get("means", {})
    stds = model.get("stds", {})
    coeffs = model.get("coefficients", {})
    score = float(model.get("intercept", 0.0))
    for feature in FEATURE_COLUMNS:
        value = float(row.get(feature) or 0.0)
        centered = (value - float(means.get(feature, 0.0))) / max(float(stds.get(feature, 1.0)), 1e-8)
        score += centered * float(coeffs.get(feature, 0.0))
    probability = 1.0 / (1.0 + np.exp(-np.clip(score, -20, 20)))
    return round((probability - 0.5) * 0.8, 3)


def attach_refinement_preview(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    base_rows = list(rows)
    if not base_rows:
        return []

    frame = build_refinement_feature_frame(base_rows)
    model = _fit_lightweight_logistic(frame)

    preview_rows: List[Dict[str, Any]] = []
    for row in frame.to_dict(orient="records"):
        item = dict(row)
        delta = apply_refinement_delta(item, model=model)

        risk_score = float(item.get("risk_score") or 0.0)

        item["ml_refinement_delta_preview"] = delta
        item["refined_risk_score_preview"] = round(
            max(risk_score, risk_score + delta),
            3,
        )
        item["ml_model_coefficients"] = model.get("coefficients", {})

        preview_rows.append(item)

    return preview_rows