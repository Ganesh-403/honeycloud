"""
ML Engine management routes (admin-only).

  POST /api/v1/ml/train       – train model on all stored events
  GET  /api/v1/ml/status      – current model status and feature info
  POST /api/v1/ml/predict     – run a single-event prediction (debug/demo)
"""
from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_event_service, get_ml_detector
from app.core.logging import get_logger
from app.core.security import get_current_user, require_admin
from app.ml.detector import MLThreatDetector
from app.ml.features import FEATURE_NAMES
from app.schemas.auth import UserInDB
from app.schemas.event import EventIngest
from app.services.event_service import EventService

router = APIRouter(prefix="/ml", tags=["ML Engine"])
logger = get_logger(__name__)


@router.get("/status", summary="ML model status")
def ml_status(
    current_user: UserInDB = Depends(get_current_user),
    detector: MLThreatDetector = Depends(get_ml_detector),
):
    """
    Show whether the model is trained, the features it uses,
    and basic model parameters.
    """
    return {
        "is_trained":     detector.is_ready,
        "model_type":     "IsolationForest",
        "contamination":  detector._contamination,
        "feature_count":  len(FEATURE_NAMES),
        "features":       FEATURE_NAMES,
        "model_path":     str(detector._model_path if hasattr(detector, "_model_path") else "data/ml_model.pkl"),
        "status":         "ready" if detector.is_ready else "untrained – POST /ml/train to initialise",
    }


@router.post("/train", summary="Train ML model on stored events (admin)")
def train_model(
    current_user: UserInDB = Depends(require_admin),
    svc: EventService = Depends(get_event_service),
    detector: MLThreatDetector = Depends(get_ml_detector),
):
    """
    Admin-only. Trains (or re-trains) the IsolationForest on all events
    currently stored in the database, then persists the model to disk.

    Minimum 50 events required. Returns training statistics.
    """
    events = svc.get_all_events()
    if len(events) < 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Need at least 50 events to train; have {len(events)}. "
                   "Run /simulate first to generate data.",
        )

    event_dicts = []
    for e in events:
        event_dicts.append({
            "service":    e.service,
            "username":   e.username or "",
            "password":   e.password or "",
            "command":    e.command or "",
            "source_port": e.source_port or 0,
            "timestamp":  e.timestamp,
        })

    success = detector.train(event_dicts)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Training failed. Check server logs for details.",
        )

    detector.save()
    logger.info("ML model trained by admin '%s' on %d events.", current_user.username, len(events))

    return {
        "status":         "success",
        "trained_on":     len(events),
        "model_type":     "IsolationForest",
        "features_used":  FEATURE_NAMES,
        "model_saved_to": "data/ml_model.pkl",
        "message":        "Model trained and persisted. All future ingest events will be classified.",
    }


@router.post("/predict", summary="Run ML prediction on a sample event (debug)")
def predict_event(
    payload: EventIngest,
    current_user: UserInDB = Depends(get_current_user),
    detector: MLThreatDetector = Depends(get_ml_detector),
):
    """
    Run the ML classifier on a manually supplied event without persisting it.
    Useful for demos and debugging the model's behaviour.
    """
    if not detector.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model not yet trained. POST /ml/train first.",
        )

    prediction = detector.predict(payload.model_dump())
    from app.ml.features import extract
    import numpy as np
    features = extract(payload.model_dump()).flatten().tolist()

    return {
        "input":      payload.model_dump(),
        "prediction": prediction,
        "features":   dict(zip(FEATURE_NAMES, features)),
        "interpretation": {
            "benign":    "Normal-looking traffic, low threat.",
            "anomaly":   "Unusual pattern – watch this IP.",
            "malicious": "High-confidence threat – consider blocking.",
            "unknown":   "Model not trained yet.",
        }.get(prediction["label"], ""),
    }
