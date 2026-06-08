"""
Optional DecisionTree baseline for technique classification.
Runs when rule-based accuracy < 80% or on demand. Compares accuracy and prints feature importances.
"""
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder

import pandas as pd

# Boolean and numeric feature columns for ML
FEATURE_COLS = [
    "has_base64",
    "is_persistence_attempt",
    "has_enc_flags",
    "has_powershell_process",
    "has_invoke_keywords",
    "is_office_to_powershell",
    "is_office_spawn",
    "has_lsass_mention",
    "has_procdump_minidump",
    "has_comsvcs_rundll32",
    "has_handle_taskmgr_parent",
    "has_run_registry",
    "has_reg_exe",
    "has_set_itemproperty",
    "is_suspicious_parent",
    "is_elevated",
    "cmdline_has_url",
    "network_outbound_flag",
    "cmdline_entropy",
    "cmdline_length",
]


def run_baseline_ml(
    df: pd.DataFrame,
    rule_accuracy: float,
    max_depth: int = 10,
    random_state: int = 42,
) -> float:
    """
    Fit DecisionTree on features, predict technique_id.
    Returns ML accuracy. Prints comparison and feature importances.
    """
    avail = [c for c in FEATURE_COLS if c in df.columns]
    if len(avail) < 5:
        print("Baseline ML: too few feature columns available, skipping.")
        return 0.0

    X = df[avail].copy()
    X = X.fillna(0)
    # Encode bools as 0/1
    for c in X.columns:
        if X[c].dtype == bool or X[c].dtype == "object":
            X[c] = (X[c] == True) | (X[c].astype(str).str.lower() == "true")
            X[c] = X[c].astype(int)
    y = df["technique_id"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    X_train = X
    y_train = y_enc

    clf = DecisionTreeClassifier(max_depth=max_depth, random_state=random_state)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_train)
    ml_acc = (y_pred == y_train).mean()

    print(f"\n--- Baseline ML (DecisionTree) ---")
    print(f"  Rule-based accuracy: {rule_accuracy:.2%}")
    print(f"  ML accuracy:         {ml_acc:.2%}")

    print("\n  Top feature importances:")
    imp = pd.Series(clf.feature_importances_, index=avail).sort_values(ascending=False)
    for feat, val in imp.head(10).items():
        print(f"    {feat}: {val:.3f}")

    return float(ml_acc)
