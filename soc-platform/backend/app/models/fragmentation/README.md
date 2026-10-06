Drop your trained fragmentation flood model here, named exactly:

- `xgb_model.pkl` - trained XGBoost classifier (`predict_proba` compatible)
- `scaler.pkl` - fitted scaler used at training time (e.g. `sklearn.preprocessing.StandardScaler`)
- `feature_names.json` - JSON array of feature names, in the exact column order the scaler/model expect
- `dl_model.h5` - optional Keras/TensorFlow model for the hybrid score (omit if XGBoost-only)

Once all three required files exist, `app/detection/base.load_model_bundle("fragmentation")`
automatically picks them up and `app/detection/fragmentation.py` switches from the rate-based
rule to `run_hybrid()` - no code changes needed. If your feature engineering differs from the
placeholder `app/detection/fragmentation.py:FEATURES` list, update `extract_features()` in that
file to compute whatever columns `feature_names.json` lists.
