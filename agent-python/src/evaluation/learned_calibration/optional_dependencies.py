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

def _load_sklearn() -> Mapping[str, Any] | None:
    try:
        from sklearn import metrics
        from sklearn.dummy import DummyClassifier
        from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
    except ImportError:
        return None
    return {
        "DummyClassifier": DummyClassifier,
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier,
        "LogisticRegression": LogisticRegression,
        "RandomForestClassifier": RandomForestClassifier,
        "train_test_split": train_test_split,
        "metrics": metrics,
    }

