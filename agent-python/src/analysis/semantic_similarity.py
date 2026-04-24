from __future__ import annotations

import math
import re
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache
from typing import Dict, Iterable, List, Sequence

from config import get_settings

TOKEN_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_\-\.]{1,}")


@lru_cache(maxsize=1)
def _load_sentence_transformer():
    settings = get_settings()
    if not settings.semantic.enabled:
        return None
    if settings.semantic.backend not in {"sentence_transformers"}:
        return None
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore

        kwargs = {}
        if not settings.semantic.allow_remote_model_download:
            kwargs["local_files_only"] = True
        return SentenceTransformer(settings.semantic.model_name, **kwargs)
    except Exception:
        return None


@lru_cache(maxsize=4096)
def tokenize(text: str) -> tuple[str, ...]:
    return tuple(TOKEN_RE.findall((text or "").lower()))


def _char_ngrams(text: str, n: int = 3) -> Counter[str]:
    normalized = re.sub(r"\s+", " ", (text or "").lower()).strip()
    if len(normalized) < n:
        return Counter({normalized: 1}) if normalized else Counter()
    return Counter(normalized[i : i + n] for i in range(len(normalized) - n + 1))


@lru_cache(maxsize=2048)
def _fallback_vector(text: str) -> Dict[str, float]:
    grams = _char_ngrams(text)
    if not grams:
        return {}
    norm = math.sqrt(sum(value * value for value in grams.values())) or 1.0
    return {key: value / norm for key, value in grams.items()}


def _cosine_sparse(left: Dict[str, float], right: Dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    if len(left) > len(right):
        left, right = right, left
    return max(0.0, min(1.0, sum(value * right.get(key, 0.0) for key, value in left.items())))


@lru_cache(maxsize=2048)
def _sentence_embedding(text: str):
    model = _load_sentence_transformer()
    if model is None:
        return None
    try:
        return model.encode(text or "", normalize_embeddings=True)
    except Exception:
        return None


@lru_cache(maxsize=2048)
def semantic_similarity(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    emb_a = _sentence_embedding(text_a)
    emb_b = _sentence_embedding(text_b)
    if emb_a is not None and emb_b is not None:
        try:
            import numpy as np

            return float(max(0.0, min(1.0, float(np.dot(emb_a, emb_b)))))
        except Exception:
            pass

    sparse_score = _cosine_sparse(_fallback_vector(text_a), _fallback_vector(text_b))
    seq_score = SequenceMatcher(None, (text_a or "").lower(), (text_b or "").lower()).ratio()
    token_score = token_jaccard(tokenize(text_a), tokenize(text_b))
    return round((sparse_score * 0.45) + (seq_score * 0.25) + (token_score * 0.30), 4)


def token_jaccard(tokens_a: Sequence[str], tokens_b: Sequence[str]) -> float:
    set_a = set(tokens_a)
    set_b = set(tokens_b)
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def weighted_jaccard(tokens_a: Iterable[str], tokens_b: Iterable[str]) -> float:
    counts_a = Counter(tokens_a)
    counts_b = Counter(tokens_b)
    keys = set(counts_a) | set(counts_b)
    if not keys:
        return 0.0
    numerator = sum(min(counts_a.get(k, 0), counts_b.get(k, 0)) for k in keys)
    denominator = sum(max(counts_a.get(k, 0), counts_b.get(k, 0)) for k in keys)
    return numerator / denominator if denominator else 0.0


def top_shared_terms(tokens_a: Sequence[str], tokens_b: Sequence[str], limit: int = 8) -> List[str]:
    shared = Counter(tokens_a) & Counter(tokens_b)
    return [term for term, _ in shared.most_common(limit)]
