"""
ML Engine management routes (admin-only).

  POST /api/v1/ml/train       – train model on all stored events
  GET  /api/v1/ml/status      – current model status and feature info
  POST /api/v1/ml/predict     – run a single-event prediction (debug/demo)
  POST /api/v1/ml/train-rf    – train Random Forest model
  POST /api/v1/ml/predict-rf  – run RF prediction on a sample event
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.api.deps import get_event_service, get_ml_detector, get_rf_detector, get_audit_repo
from app.db.session import get_db
from app.core.logging import get_logger
from app.core.security import get_current_user, require_admin
from app.ml.detector import MLThreatDetector
from app.ml.rf_detector import RFDetector
from app.ml.features import FEATURE_NAMES, extract_with_command
from app.schemas.auth import UserInDB
from app.schemas.event import EventIngest
from app.services.event_service import EventService

router = APIRouter(prefix="/ml", tags=["ML Engine"])
logger = get_logger(__name__)


@router.get("/status", summary="ML model status")
def ml_status(
    current_user: UserInDB = Depends(get_current_user),
    detector: MLThreatDetector = Depends(get_ml_detector),
    rf_detector: RFDetector = Depends(get_rf_detector),
):
    """
    Show whether the models are trained, the features they use,
    and basic model parameters.
    """
    rf_importances = rf_detector.get_feature_importances() if rf_detector.is_ready else {}
    return {
        "lstm": {
            "is_trained":    detector.is_ready,
            "model_type":    "Keras LSTM (numerical + command sequence)",
            "feature_count": len(FEATURE_NAMES),
            "features":      FEATURE_NAMES,
            "model_path":    str(detector._model_path if hasattr(detector, "_model_path") else "data/ml_model.keras"),
            "status":        "ready" if detector.is_ready else "untrained – POST /ml/train to initialise",
        },
        "random_forest": {
            "is_trained":           rf_detector.is_ready,
            "model_type":           "Scikit-Learn Random Forest (100 estimators)",
            "feature_count":        len(FEATURE_NAMES),
            "features":             FEATURE_NAMES,
            "model_path":           "data/rf_model.pkl",
            "feature_importances":  rf_importances,
            "status":               "ready" if rf_detector.is_ready else "untrained – POST /ml/train-rf to initialise",
        },
    }


@router.post("/train", summary="Train LSTM model on stored events (admin)")
def train_model(
    request: Request,
    current_user: UserInDB = Depends(require_admin),
    svc: EventService = Depends(get_event_service),
    detector: MLThreatDetector = Depends(get_ml_detector),
    db: Session = Depends(get_db),
):
    """
    Admin-only. Trains (or re-trains) the LSTM classifier on all events
    currently stored in the database, then persists the model to disk.

    Minimum 50 events required. Returns training statistics.
    """
    events = svc.get_all_events()
    if len(events) < 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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
            "severity":   e.severity,
        })

    success = detector.train(event_dicts)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Training failed. Check server logs for details.",
        )

    detector.save()
    logger.info("ML model trained by admin '%s' on %d events.", current_user.username, len(events))

    # Log action to audit trail
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=current_user.username,
        action="TRAIN_ML",
        client_ip=client_ip,
        target="data/ml_model.keras",
        description=f"Trained LSTM threat detector model on {len(events)} events successfully.",
    )

    return {
        "status":         "success",
        "trained_on":     len(events),
        "model_type":     "Keras LSTM (numerical + command sequence)",
        "features_used":  FEATURE_NAMES,
        "model_saved_to": "data/ml_model.keras (+ tokenizer.pkl)",
        "message":        "Model trained and persisted. All future ingest events will be classified.",
    }


@router.post("/train-rf", summary="Train Random Forest model on stored events (admin)")
def train_rf_model(
    request: Request,
    current_user: UserInDB = Depends(require_admin),
    svc: EventService = Depends(get_event_service),
    rf_detector: RFDetector = Depends(get_rf_detector),
    db: Session = Depends(get_db),
):
    """
    Admin-only. Trains the Random Forest classifier as a secondary ML model
    for cross-verification alongside the LSTM.
    """
    events = svc.get_all_events()
    if len(events) < 50:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Need at least 50 events to train; have {len(events)}. "
                   "Run /simulate first to generate data.",
        )

    event_dicts = []
    for e in events:
        event_dicts.append({
            "service":     e.service,
            "username":    e.username or "",
            "password":    e.password or "",
            "command":     e.command or "",
            "source_port": e.source_port or 0,
            "timestamp":   e.timestamp,
            "severity":    e.severity,
        })

    success = rf_detector.train(event_dicts)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="RF training failed. Check server logs for details.",
        )

    logger.info("RF model trained by admin '%s' on %d events.", current_user.username, len(events))

    # Log action to audit trail
    client_ip = request.client.host if request.client else "0.0.0.0"
    get_audit_repo(db).log(
        username=current_user.username,
        action="TRAIN_RF",
        client_ip=client_ip,
        target="data/rf_model.pkl",
        description=f"Trained Random Forest model on {len(events)} events successfully.",
    )

    return {
        "status":              "success",
        "trained_on":          len(events),
        "model_type":          "Scikit-Learn Random Forest (100 estimators)",
        "features_used":       FEATURE_NAMES,
        "feature_importances": rf_detector.get_feature_importances(),
        "model_saved_to":      "data/rf_model.pkl",
        "message":             "Random Forest model trained and persisted.",
    }


@router.post("/predict", summary="Run LSTM prediction on a sample event (debug)")
def predict_event(
    payload: EventIngest,
    current_user: UserInDB = Depends(get_current_user),
    detector: MLThreatDetector = Depends(get_ml_detector),
):
    """
    Run the LSTM classifier on a manually supplied event without persisting it.
    Useful for demos and debugging the model's behaviour.
    """
    if not detector.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML model not yet trained. POST /ml/train first.",
        )

    prediction = detector.predict(payload.model_dump())
    numerical_features, command_sequence = extract_with_command(payload.model_dump())

    return {
        "input":      payload.model_dump(),
        "prediction": prediction,
        "features":   dict(zip(FEATURE_NAMES, numerical_features.flatten().tolist())),
        "command_sequence": command_sequence.flatten().tolist(),
        "interpretation": {
            "benign":    "Normal-looking traffic, low threat.",
            "anomaly":   "Unusual pattern – watch this IP.",
            "malicious": "High-confidence threat – consider blocking.",
            "unknown":   "Model not trained yet.",
        }.get(prediction["label"], ""),
    }


@router.post("/predict-rf", summary="Run Random Forest prediction on a sample event (debug)")
def predict_rf_event(
    payload: EventIngest,
    current_user: UserInDB = Depends(get_current_user),
    rf_detector: RFDetector = Depends(get_rf_detector),
):
    """
    Run the Random Forest classifier on a manually supplied event.
    Returns class probabilities for benign/suspicious/malicious.
    """
    if not rf_detector.is_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RF model not yet trained. POST /ml/train-rf first.",
        )

    prediction = rf_detector.predict(payload.model_dump())
    from app.ml.features import extract
    features = extract(payload.model_dump())

    return {
        "input":         payload.model_dump(),
        "prediction":    prediction,
        "features":      dict(zip(FEATURE_NAMES, features.flatten().tolist())),
        "interpretation": {
            "benign":     "Normal-looking traffic, low threat.",
            "suspicious": "Unusual pattern – warrants further investigation.",
            "malicious":  "High-confidence threat – consider blocking.",
            "unknown":    "Model not trained yet.",
        }.get(prediction["label"], ""),
    }
