"""Unit tests for ML feature extraction and threat detector."""
import numpy as np
import pytest


class TestFeatureExtraction:
    def test_feature_count(self):
        from app.ml.features import extract, NUM_FEATURES
        event = {"service": "SSH", "username": "root", "password": "pass", "command": "ls", "source_port": 22}
        features = extract(event)
        assert features.shape == (1, NUM_FEATURES)

    def test_empty_event(self):
        from app.ml.features import extract, NUM_FEATURES
        features = extract({})
        assert features.shape == (1, NUM_FEATURES)
        assert not np.any(np.isnan(features))

    def test_dangerous_pattern_detected(self):
        from app.ml.features import extract, FEATURE_NAMES
        idx = FEATURE_NAMES.index("dangerous_pattern_count")
        safe = extract({"command": "ls"}).flatten()[idx]
        danger = extract({"command": "rm -rf /"}).flatten()[idx]
        assert danger > safe

    def test_root_user_flag(self):
        from app.ml.features import extract, FEATURE_NAMES
        idx = FEATURE_NAMES.index("is_root_user")
        assert extract({"username": "root"}).flatten()[idx] == 1.0
        assert extract({"username": "alice"}).flatten()[idx] == 0.0

    def test_anon_user_flag(self):
        from app.ml.features import extract, FEATURE_NAMES
        idx = FEATURE_NAMES.index("is_anonymous_user")
        assert extract({"username": "anonymous"}).flatten()[idx] == 1.0
        assert extract({"username": "root"}).flatten()[idx] == 0.0

    def test_service_port_mapping(self):
        from app.ml.features import extract, FEATURE_NAMES
        idx = FEATURE_NAMES.index("service_port")
        assert extract({"service": "SSH"}).flatten()[idx] == 22.0
        assert extract({"service": "FTP"}).flatten()[idx] == 21.0
        assert extract({"service": "HTTP"}).flatten()[idx] == 80.0


class TestMLDetector:
    def test_untrained_returns_unknown(self):
        from app.ml.detector import MLThreatDetector
        d = MLThreatDetector.__new__(MLThreatDetector)
        d._model = None; d._trained = False; d._contamination = 0.1
        result = d.predict({"service": "SSH", "username": "root"})
        assert result["label"] == "unknown"
        assert result["score"] == 0.0

    def test_train_requires_minimum_samples(self):
        from app.ml.detector import MLThreatDetector
        d = MLThreatDetector.__new__(MLThreatDetector)
        d._model = None; d._trained = False; d._contamination = 0.1
        result = d.train([{"service": "SSH"} for _ in range(10)])
        assert result is False

    def test_train_and_predict(self, tmp_path, monkeypatch):
        from app.ml.detector import MLThreatDetector
        import app.ml.detector as det_mod
        monkeypatch.setattr(det_mod, "MODEL_PATH", tmp_path / "model.pkl")
        d = MLThreatDetector()
        events = [
            {"service": "SSH", "username": "root", "password": "x", "command": "ls", "source_port": 22}
            for _ in range(60)
        ]
        assert d.train(events) is True
        assert d.is_ready is True
        result = d.predict(events[0])
        assert result["label"] in ("benign", "anomaly", "malicious")
        assert 0.0 <= result["score"] <= 1.0

    def test_save_and_reload(self, tmp_path, monkeypatch):
        from app.ml.detector import MLThreatDetector
        import app.ml.detector as det_mod
        monkeypatch.setattr(det_mod, "MODEL_PATH", tmp_path / "model.pkl")
        d = MLThreatDetector()
        events = [{"service": "HTTP", "username": f"u{i}", "command": "GET /", "source_port": 80}
                  for i in range(60)]
        d.train(events)
        d.save()
        # New instance should load the saved model
        d2 = MLThreatDetector()
        assert d2.is_ready is True
