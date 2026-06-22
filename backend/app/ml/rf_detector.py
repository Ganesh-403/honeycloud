"""
Random Forest threat detector – Scikit-Learn-based secondary ML model.

Runs alongside the primary LSTM detector for cross-verification.
Classifies events as: Benign (0), Suspicious (1), or Malicious (2).

Features used:
  - username_len, password_len, command_len
  - service_port, source_port
  - hour_of_day
  - dangerous_pattern_count
  - is_root_user, is_anonymous_user
  - has_command
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from app.core.logging import get_logger
from app.ml.features import extract, FEATURE_NAMES

logger = get_logger(__name__)

RF_MODEL_PATH = Path("data/rf_model.pkl")
MIN_SAMPLES = 50
LABEL_MAP = {0: "benign", 1: "suspicious", 2: "malicious"}
REVERSE_LABEL_MAP = {"benign": 0, "suspicious": 1, "malicious": 2}


class RFDetector:
    """Scikit-Learn Random Forest threat classifier."""

    def __init__(self):
        self._model: Optional[RandomForestClassifier] = None
        self._trained = False
        self._load_if_exists()

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._trained

    def predict(self, event: dict) -> dict[str, object]:
        """
        Predict threat class for a single event.
        Returns {"label": str, "score": float, "probabilities": dict}.
        """
        if not self._trained:
            return {"label": "unknown", "score": 0.0, "probabilities": {}}

        try:
            features = extract(event)  # shape (1, NUM_FEATURES)
            prediction = self._model.predict(features)[0]
            probabilities = self._model.predict_proba(features)[0]

            label = LABEL_MAP.get(int(prediction), "unknown")

            # Score = max probability of the predicted class
            score = float(max(probabilities))

            prob_dict = {
                LABEL_MAP[i]: round(float(p), 4)
                for i, p in enumerate(probabilities)
                if i in LABEL_MAP
            }

            return {"label": label, "score": round(score, 4), "probabilities": prob_dict}

        except Exception as exc:
            logger.error("RF prediction error: %s", exc)
            return {"label": "unknown", "score": 0.0, "probabilities": {}}

    def train(self, events: list[dict]) -> bool:
        """
        Train the Random Forest model on event dicts.
        Events must contain a 'severity' field for automatic labelling.
        Returns True on success.
        """
        if len(events) < MIN_SAMPLES:
            logger.warning(
                "RF: Not enough data to train (%d < %d). Skipping.",
                len(events), MIN_SAMPLES,
            )
            return False

        try:
            X_list = []
            y_list = []

            for e in events:
                features = extract(e).flatten()
                X_list.append(features)

                # Auto-label based on severity
                severity = (e.get("severity") or "MEDIUM").upper()
                if severity in ("CRITICAL", "HIGH"):
                    y_list.append(2)  # malicious
                elif severity == "MEDIUM":
                    y_list.append(1)  # suspicious
                else:
                    y_list.append(0)  # benign

            X = np.array(X_list)
            y = np.array(y_list)

            self._model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X, y)
            self._trained = True
            self.save()

            # Log feature importances
            importances = dict(zip(FEATURE_NAMES, self._model.feature_importances_))
            top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
            logger.info(
                "RF model trained on %d samples. Top features: %s",
                len(events),
                [(f, round(v, 4)) for f, v in top_features],
            )
            return True

        except Exception as exc:
            logger.error("RF training failed: %s", exc)
            return False

    def save(self) -> None:
        """Persist model to disk."""
        RF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with RF_MODEL_PATH.open("wb") as fh:
            pickle.dump(self._model, fh)
        logger.info("RF model saved to %s", RF_MODEL_PATH)

    def get_feature_importances(self) -> dict[str, float]:
        """Return feature importance scores (requires trained model)."""
        if not self._trained:
            return {}
        return {
            name: round(float(imp), 4)
            for name, imp in zip(FEATURE_NAMES, self._model.feature_importances_)
        }

    # ── Private ───────────────────────────────────────────────────────────────

    def _load_if_exists(self) -> None:
        if not RF_MODEL_PATH.exists():
            logger.info("No saved RF model found – starting untrained.")
            return
        try:
            with RF_MODEL_PATH.open("rb") as fh:
                self._model = pickle.load(fh)
            self._trained = True
            logger.info("RF model loaded from %s", RF_MODEL_PATH)
        except Exception as exc:
            logger.warning("Failed to load RF model: %s", exc)
