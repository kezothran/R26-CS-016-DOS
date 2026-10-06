"""Shared model loading + hybrid scoring, lifted verbatim (formula-wise) from both prototypes:

    hybrid = xgb_weight * xgb_prob + cnn_weight * dl_prob

including the DL reshape-fallback: both prototypes reshape the scaled feature matrix to the
loaded model's `input_shape` and fall back to a copy of the XGBoost probability if the DL model
raises (e.g. wrong shape, or TensorFlow unavailable).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


@dataclass
class ModelBundle:
    attack_type: str
    trained: bool
    features: list[str]
    xgb_model: object | None = None
    scaler: object | None = None
    dl_model: object | None = None
    dl_input_shape: tuple | None = None


def load_model_bundle(attack_type: str) -> ModelBundle:
    """Loads models/<attack_type>/{xgb_model.pkl, scaler.pkl, dl_model.h5 (optional), feature_names.json}.
    If xgb_model.pkl/scaler.pkl/feature_names.json are missing, returns an untrained bundle -
    the attack module falls back to its rule-based heuristic instead of ML inference.
    """
    d = MODELS_DIR / attack_type
    feature_file = d / "feature_names.json"
    xgb_file = d / "xgb_model.pkl"
    scaler_file = d / "scaler.pkl"
    dl_file = d / "dl_model.h5"

    if not (feature_file.exists() and xgb_file.exists() and scaler_file.exists()):
        return ModelBundle(attack_type=attack_type, trained=False, features=[])

    with open(feature_file) as f:
        features = json.load(f)
    if features and isinstance(features[0], list):  # ICMP's feature_names.json is nested [[...]]
        features = features[0]

    # joblib, not pickle - it's the scikit-learn-recommended loader for model artifacts and
    # reads both joblib.dump's and plain pickle.dump's output, whereas plain pickle.load chokes
    # on some joblib.dump'd files (STACK_GLOBAL requires str) depending on numpy/sklearn version
    # skew between the training and serving environments.
    xgb_model = joblib.load(xgb_file)
    scaler = joblib.load(scaler_file)

    dl_model = None
    dl_input_shape = None
    if dl_file.exists():
        try:
            import tensorflow as tf

            tf.get_logger().setLevel("ERROR")
            dl_model = tf.keras.models.load_model(str(dl_file), compile=False)
            dl_input_shape = dl_model.input_shape
        except Exception:
            dl_model = None

    return ModelBundle(
        attack_type=attack_type,
        trained=True,
        features=features,
        xgb_model=xgb_model,
        scaler=scaler,
        dl_model=dl_model,
        dl_input_shape=dl_input_shape,
    )


def run_hybrid(records: list[dict], cfg: dict, bundle: ModelBundle) -> list[dict]:
    if not records or not bundle.trained:
        return records

    xw = cfg.get("xgb_weight", 0.6)
    cw = cfg.get("cnn_weight", 0.4)
    thresh = cfg.get("threshold", 0.5)

    X = np.array([[r[f] for f in bundle.features] for r in records])
    X = np.nan_to_num(np.where(np.isinf(X), 0, X))
    Xsc = bundle.scaler.transform(X)
    xprb = bundle.xgb_model.predict_proba(Xsc)[:, 1]

    dprb = np.zeros(len(records))
    if bundle.dl_model is not None:
        try:
            n_features = len(bundle.features)
            shape = bundle.dl_input_shape
            if shape and len(shape) == 3 and shape[1] == n_features:
                Xd = Xsc.reshape(-1, n_features, 1)
            else:
                Xd = Xsc.reshape(-1, 1, n_features)
            dprb = np.clip(bundle.dl_model.predict(Xd, verbose=0).flatten(), 0, 1)
        except Exception:
            dprb = xprb.copy()

    hprb = xw * xprb + cw * dprb if bundle.dl_model is not None else xprb.copy()

    for i, r in enumerate(records):
        r["xp"] = float(xprb[i])
        r["dp"] = float(dprb[i])
        r["hp"] = float(hprb[i])
        r["attack"] = int(hprb[i] > thresh)

    return records


def assign_tier_by_pps(pps: float) -> str:
    if pps > 10000:
        return "CRITICAL"
    if pps > 5000:
        return "HIGH"
    if pps > 1000:
        return "MEDIUM"
    return "LOW"
