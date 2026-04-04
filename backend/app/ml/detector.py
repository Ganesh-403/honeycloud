"""
MLThreatDetector – Isolation Forest anomaly detection.

Lifecycle:
  1. On startup, try to load a saved model from MODEL_PATH.
  2. If no saved model exists, enter "untrained" state and return
     label="unknown" until .train() is called with real data.
  3. After training (or loading), .predict() classifies every event.
  4. Call .save() to persist the trained model for future restarts.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest

from app.core.logging import get_logger
from app.ml.features import NUM_FEATURES, extract

logger = get_logger(__name__)

MODEL_PATH = Path("data/ml_model.pkl")
MIN_SAMPLES_TO_TRAIN = 50   # won't train on tiny datasets


class MLThreatDetector:
    """
    Wraps scikit-learn IsolationForest with a standardised
    label → (benign | anomaly | malicious | unknown) mapping.
    """

    def __init__(self, contamination: float = 0.1):
        self._model: Optional[IsolationForest] = None
        self._contamination = contamination
        self._trained = False
        self._load_if_exists()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._trained

    def predict(self, event: dict) -> dict[str, object]:
        """
        Returns {"label": str, "score": float}.
        Falls back to {"label": "unknown", "score": 0.0} if not trained.
        """
        if not self._trained:
            return {"label": "unknown", "score": 0.0}

        try:
            features = extract(event)
            raw_pred  = self._model.predict(features)[0]           # 1 or -1
            raw_score = float(self._model.decision_function(features)[0])
            # decision_function: higher = more normal, lower = more anomalous
            # We invert and normalise to [0, 1] threat-score
            threat_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 3)

            if raw_pred == -1:
                label = "malicious" if threat_score >= 0.6 else "anomaly"
            else:
                label = "benign"

            return {"label": label, "score": threat_score}

        except Exception as exc:
            logger.error("ML prediction error: %s", exc)
            return {"label": "unknown", "score": 0.0}

    def train(self, events: list[dict]) -> bool:
        """
        Train (or re-train) the model on a list of event dicts.
        Returns True on success.
        """
        if len(events) < MIN_SAMPLES_TO_TRAIN:
            logger.warning(
                "Not enough data to train (%d < %d). Skipping.",
                len(events), MIN_SAMPLES_TO_TRAIN,
            )
            return False

        try:
            X = np.vstack([extract(e) for e in events])
            self._model = IsolationForest(
                contamination=self._contamination,
                n_estimators=200,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X)
            self._trained = True
            logger.info("ML model trained on %d samples.", len(events))
            return True
        except Exception as exc:
            logger.error("ML training failed: %s", exc)
            return False

    def save(self) -> None:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with MODEL_PATH.open("wb") as fh:
            pickle.dump({"model": self._model, "trained": self._trained}, fh)
        logger.info("ML model saved to %s", MODEL_PATH)

    # ── Private ───────────────────────────────────────────────────────────────

    def _load_if_exists(self) -> None:
        if not MODEL_PATH.exists():
            logger.info("No saved ML model found at %s – starting untrained.", MODEL_PATH)
            return
        try:
            with MODEL_PATH.open("rb") as fh:
                state = pickle.load(fh)
            self._model   = state["model"]
            self._trained = state["trained"]
            logger.info("ML model loaded from %s", MODEL_PATH)
        except Exception as exc:
            logger.warning("Failed to load ML model: %s", exc)
