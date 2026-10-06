Trained SYN flood model, wired in 2026-08-25:

- `xgb_model.pkl` - 5-class `multi:softprob` XGBoost classifier (pickled with `dill`, not plain
  pickle/joblib - see `requirements.txt`)
- `scaler.pkl` - fitted `StandardScaler`, 81 features (its own `feature_names_in_` is the
  authoritative feature list/order - `feature_names.json` matches it exactly)
- `feature_names.json` - the 81 CICFlowMeter/CIC-DDoS2019-style bidirectional flow columns
- `dl_model.h5` - Conv1D + BiLSTM, also 5-class softmax, input shape `(None, 81, 1)`

No training notebook/script was available (source: `C:\Users\VICTUS\Downloads\trained\`, dropped
in with no accompanying code) - two things had to be reverse-engineered rather than confirmed:

1. **The label mapping is unverified.** `app/detection/syn.py::_run_multiclass_hybrid()` assumes
   class 0 = benign, classes 1-4 = attack subtypes ("attack probability" = 1 - P(class 0)). If
   you ever find the original training source, confirm this against it.
2. **The model was very likely trained on individual short per-connection CICFlowMeter flows**
   (`scaler.mean_` for `Total Fwd Packets` is ~3, i.e. training flows average ~3 packets each),
   **not** the aggregated-per-attacker-per-5-second-window flows this platform's live capture
   produces (`extract_features()` deliberately aggregates one attacker's whole window into one
   flow, the same way the original rule-based version did, to survive randomized source ports -
   see the module docstring). This is the same class of train/live scale mismatch already found
   in the ICMP and UDP models: live confidence scores are noisy/uninformative, not a reliable
   attack-probability estimate.

Because of both caveats, `score()` never trusts this model's confidence alone - the proven
packet-rate rule (`n_packets > MIN_SYN_COUNT`) is always sufficient by itself to flag a flood;
the model can only add a flag on top of it, never block one. Confidence numbers still display on
the dashboard for reference, but treat them as informational, not authoritative.
