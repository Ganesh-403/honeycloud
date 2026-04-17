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
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Embedding, LSTM, Dense, concatenate
from app.ml.features import NUM_FEATURES, MAX_COMMAND_SEQUENCE_LENGTH, MAX_VOCAB_SIZE, extract, fit_tokenizer, get_tokenizer

from app.core.logging import get_logger
from app.ml.features import NUM_FEATURES, extract

logger = get_logger(__name__)

MODEL_PATH = Path("data/ml_model.h5") # Keras models are typically saved in HDF5 format
TOKENIZER_PATH = Path("data/tokenizer.pkl")
MIN_SAMPLES_TO_TRAIN = 50   # won't train on tiny datasets


class MLThreatDetector:
    def _build_lstm_model(self) -> Model:
        # Numerical input branch
        numerical_input = Input(shape=(NUM_FEATURES,), name='numerical_input')
        numerical_branch = Dense(64, activation='relu')(numerical_input)

        # Command sequence input branch
        command_input = Input(shape=(MAX_COMMAND_SEQUENCE_LENGTH,), name='command_input')
        embedding_layer = Embedding(MAX_VOCAB_SIZE, 128, input_length=MAX_COMMAND_SEQUENCE_LENGTH)(command_input)
        lstm_branch = LSTM(64)(embedding_layer)

        # Concatenate branches
        merged = concatenate([numerical_branch, lstm_branch])

        # Output layer
        output = Dense(1, activation='sigmoid')(merged) # Binary classification

        model = Model(inputs=[numerical_input, command_input], outputs=output)
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model


    """
    Wraps scikit-learn IsolationForest with a standardised
    label → (benign | anomaly | malicious | unknown) mapping.
    """

    def __init__(self, contamination: float = 0.1):
        self._model: Optional[Model] = None
        self._trained = False
        self._load_if_exists()
        if not self._trained:
            self._model = self._build_lstm_model() # Initialize model even if not trained yet

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
            numerical_features, command_sequence = extract(event)
            prediction = self._model.predict([numerical_features, command_sequence], verbose=0)[0][0]
            
            # For binary classification (0=benign, 1=malicious)
            if prediction >= 0.5:
                label = "malicious"
                threat_score = round(prediction, 3)
            else:
                label = "benign"
                threat_score = round(1 - prediction, 3) # Lower score for benign

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
            # Prepare data for LSTM
            all_numerical_features = []
            all_commands = []
            labels = [] # Assuming a binary label for simplicity: 0 for benign, 1 for malicious

            for e in events:
                num_feat, cmd_seq = extract(e)
                all_numerical_features.append(num_feat.flatten())
                all_commands.append(e.get("command") or "") # Store raw commands for tokenizer fitting
                # For demonstration, let's assume 'severity' can be mapped to a binary label
                # This needs to be refined based on actual data and desired ML task
                labels.append(1 if e.get("severity") in ["CRITICAL", "HIGH"] else 0)
            
            fit_tokenizer(all_commands) # Fit tokenizer on all commands
            tokenizer = get_tokenizer()
            padded_command_sequences = pad_sequences(tokenizer.texts_to_sequences(all_commands), maxlen=MAX_COMMAND_SEQUENCE_LENGTH, padding='post', truncating='post')

            X_numerical = np.array(all_numerical_features)
            y_labels = np.array(labels)

            # Rebuild model if not already built or if structure needs to change
            if self._model is None:
                self._model = self._build_lstm_model()

            self._model.fit([X_numerical, padded_command_sequences], y_labels, epochs=10, batch_size=32, verbose=0)
            self._trained = True
            self.save() # Auto-save after training
            return True
            logger.info("ML model trained on %d samples.", len(events))
            return True
        except Exception as exc:
            logger.error("ML training failed: %s", exc)
            return False

    def save(self) -> None:
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with MODEL_PATH.open("wb") as fh:
            self._model.save(MODEL_PATH)
            with TOKENIZER_PATH.open("wb") as tk_fh:
                pickle.dump(get_tokenizer(), tk_fh)
        logger.info("ML model saved to %s", MODEL_PATH)

    # ── Private ───────────────────────────────────────────────────────────────

    def _load_if_exists(self) -> None:
        if not MODEL_PATH.exists() or not TOKENIZER_PATH.exists():
            logger.info("No saved ML model or tokenizer found – starting untrained.")
            return
        try:
            self._model = tf.keras.models.load_model(MODEL_PATH)
            with TOKENIZER_PATH.open("rb") as tk_fh:
                global _tokenizer
                _tokenizer = pickle.load(tk_fh)
            self._trained = True
            logger.info("ML model and tokenizer loaded from %s and %s", MODEL_PATH, TOKENIZER_PATH)
        except Exception as exc:
            logger.warning("Failed to load ML model or tokenizer: %s", exc)
        except Exception as exc:
            logger.warning("Failed to load ML model: %s", exc)
