"""
Lightweight ML ensemble for MITRE technique classification.
Improves over rule-based and single DT: better F1 on minorities, interpretability, confidence gating.
Ensemble kept small (n_estimators=100, max_depth 10-15) so serialized size <100MB, fast for Streamlit Cloud.
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, balanced_accuracy_score, classification_report
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier

from ..config import PROCESSED_DIR, PROJECT_ROOT

# Reuse feature set from baseline_ml
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

MODELS_DIR = PROJECT_ROOT / "models"
DT_BASELINE_ACC = 0.6063
RULE_ACC = 0.1883


def load_and_prepare(csv_path: Path | None = None):
    """
    Load CSV, build X (feature matrix + optional event_type one-hot), y.
    Returns (X, y, df, feature_names, le).
    """
    path = csv_path or PROCESSED_DIR / "classified_events.csv"
    if not path.exists():
        path = PROCESSED_DIR / "combined_features.csv"
    if not path.exists():
        raise FileNotFoundError(f"No classified_events or combined_features at {PROCESSED_DIR}")

    df = pd.read_csv(path)
    avail = [c for c in FEATURE_COLS if c in df.columns]
    if len(avail) < 5:
        raise ValueError(f"Too few feature columns: {avail}")

    X = df[avail].copy()
    X = X.fillna(0)
    for c in X.columns:
        if X[c].dtype == bool or (X[c].dtype == "object" and c not in ("cmdline_entropy", "cmdline_length")):
            X[c] = (X[c] == True) | (X[c].astype(str).str.lower().isin(("true", "1", "yes")))
            X[c] = X[c].astype(int)
    if "event_type" in df.columns:
        dums = pd.get_dummies(df["event_type"], prefix="event", drop_first=True)
        X = pd.concat([X.reset_index(drop=True), dums.reset_index(drop=True)], axis=1)
    X = X.astype(float)

    y_raw = df["technique_id"].astype(str)
    le = LabelEncoder()
    y = le.fit_transform(y_raw)

    return X, y, df, list(X.columns), le


def train_ensemble(X_train, y_train, random_state: int = 42):
    """
    Train RF, ET, VotingClassifier; pick best by 3-fold f1_weighted.
    Returns (best_model, best_name, cv_score).
    """
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=12, class_weight="balanced", random_state=random_state
    )
    et = ExtraTreesClassifier(
        n_estimators=100, max_depth=12, class_weight="balanced", random_state=random_state
    )
    dt = DecisionTreeClassifier(max_depth=12, class_weight="balanced", random_state=random_state)
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=random_state)
    voting = VotingClassifier(
        [("dt", dt), ("rf", rf), ("lr", lr)], voting="soft"
    )

    candidates = [
        ("RandomForest", rf),
        ("ExtraTrees", et),
        ("VotingClassifier", voting),
    ]
    best_name = None
    best_model = None
    best_score = -1
    for name, model in candidates:
        scores = cross_val_score(model, X_train, y_train, cv=3, scoring="f1_weighted", n_jobs=-1)
        mean_score = scores.mean()
        if mean_score > best_score:
            best_score = mean_score
            best_name = name
            best_model = model
    best_model.fit(X_train, y_train)
    return best_model, best_name, best_score


def _get_importances(model):
    """Extract feature importances from RF/ET or from RF/ET inside VotingClassifier."""
    if hasattr(model, "feature_importances_"):
        return model.feature_importances_
    for est in getattr(model, "estimators_", []):
        if hasattr(est, "feature_importances_"):
            return est.feature_importances_
    return None


def predict_with_explain(model, X, feature_names, le, top_k: int = 3):
    """
    Predict labels and proba; build explanation_ml per row (top 3 contributing features).
    Returns (pred_labels, pred_proba_max, explanations).
    """
    proba = model.predict_proba(X)
    pred_enc = proba.argmax(axis=1)
    pred_proba_max = proba.max(axis=1)
    pred_labels = le.inverse_transform(pred_enc)

    importances = _get_importances(model)
    if importances is None:
        # No importances (e.g. LogisticRegression in voting); use zero and generic text
        importances = np.zeros(len(feature_names))
    imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=False)
    top_features = imp_series.head(top_k)

    explanations = []
    for i in range(len(X)):
        pred_id = pred_labels[i]
        conf = pred_proba_max[i] * 100
        parts = [f"{feat} (imp {imp_series[feat]:.2f})" for feat in top_features.index]
        expl = f"Predicted {pred_id} ({conf:.0f}% conf): Top contributors: {', '.join(parts)}."
        explanations.append(expl)
    return pred_labels, pred_proba_max * 100, explanations


def add_confidence_gate(confidence_ml: float) -> str:
    """Return action: Auto-Classify >=80, Review 50-80, Unknown/Low Conf <50."""
    if confidence_ml >= 80:
        return "Auto-Classify"
    if confidence_ml >= 50:
        return "Review"
    return "Unknown/Low Conf"


def evaluate_model(y_true, y_pred, y_proba, le):
    """Print accuracy, balanced accuracy, classification_report, crosstab. Return metrics dict."""
    y_true_str = le.inverse_transform(y_true)
    y_pred_str = le.inverse_transform(y_pred)
    acc = accuracy_score(y_true, y_pred)
    bal_acc = balanced_accuracy_score(y_true, y_pred)
    print("\n--- Classification report ---")
    print(classification_report(y_true_str, y_pred_str, zero_division=0))
    print("--- Confusion matrix ---")
    print(pd.crosstab(y_true_str, y_pred_str, margins=True))
    print(f"\nAccuracy: {acc:.2%}  Balanced accuracy: {bal_acc:.2%}")
    return {"accuracy": acc, "balanced_accuracy": bal_acc}


def run_improved_classification(csv_path=None):
    """
    Orchestrate: load, split, train, predict on full set, add columns, evaluate,
    save model + encoder + DF + plot, print sample rows and accuracy lift.
    """
    import numpy as np
    global np
    X, y, df, feature_names, le = load_and_prepare(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    best_model, best_name, cv_score = train_ensemble(X_train, y_train)
    print(f"\nBest model: {best_name} (cv f1_weighted={cv_score:.3f})")

    # Predict on full set for output DF
    pred_labels, confidence_ml, explanation_ml = predict_with_explain(
        best_model, X, feature_names, le
    )
    df = df.copy()
    df["predicted_technique_ml"] = pred_labels
    df["confidence_ml"] = confidence_ml
    df["explanation_ml"] = explanation_ml
    df["action"] = df["confidence_ml"].map(add_confidence_gate)

    # Hybrid: rule agreement when rule conf > 30 and not Unknown
    rule_conf = df.get("confidence_score", pd.Series(dtype=float)).fillna(0)
    rule_pred = df.get("predicted_technique", pd.Series(dtype=str))
    df["rule_agrees"] = (rule_conf > 30) & (rule_pred != "Unknown") & (rule_pred == df["predicted_technique_ml"])

    # Evaluate on test
    y_pred_test = best_model.predict(X_test)
    y_proba_test = best_model.predict_proba(X_test)
    metrics = evaluate_model(y_test, y_pred_test, y_proba_test, le)

    # Feature importances plot
    importances = _get_importances(best_model)
    if importances is not None:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=True).tail(10)
            fig, ax = plt.subplots(figsize=(8, 5))
            imp_series.plot.barh(ax=ax)
            ax.set_title("Top 10 feature importances")
            ax.set_xlabel("Importance")
            plt.tight_layout()
            MODELS_DIR.mkdir(parents=True, exist_ok=True)
            plot_path = PROCESSED_DIR / "feature_importances.png"
            plt.savefig(plot_path, dpi=100)
            plt.close()
            print(f"\nFeature importances plot saved to {plot_path}")
        except Exception as e:
            print(f"Could not save importances plot: {e}")
        print("\nTop 10 feature importances:")
        imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=False)
        for feat, val in imp_series.head(10).items():
            print(f"  {feat}: {val:.3f}")

    # Save model and encoder
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, MODELS_DIR / "best_ensemble.joblib", compress=3)
    joblib.dump(le, MODELS_DIR / "label_encoder.joblib", compress=3)
    print(f"\nModel saved to {MODELS_DIR / 'best_ensemble.joblib'}")

    # Save DF
    out_path = PROCESSED_DIR / "classified_improved.csv"
    df.to_csv(out_path, index=False)
    print(f"Saved to {out_path}")

    # Accuracy lift vs baseline
    acc = metrics["accuracy"]
    print(f"\n--- Accuracy lift ---")
    print(f"  Rule-based (previous): {RULE_ACC:.2%}")
    print(f"  DT baseline:           {DT_BASELINE_ACC:.2%}")
    print(f"  Ensemble (this run):   {acc:.2%}  (+{(acc - DT_BASELINE_ACC):.2%} over DT baseline)")

    # Sample rows: one correct high-conf per class, one low-conf/misclassified
    print("\n--- Sample rows (correct high-conf + misclassified/low-conf) ---")
    df["is_correct_ml"] = df["predicted_technique_ml"] == df["technique_id"]
    for tech in sorted(df["technique_id"].unique()):
        subset = df[df["technique_id"] == tech]
        correct_high = subset[subset["is_correct_ml"] & (subset["confidence_ml"] >= 70)]
        if len(correct_high) == 0:
            correct_high = subset[subset["is_correct_ml"]]
        if len(correct_high) > 0:
            row = correct_high.iloc[0]
            print(f"\n[Correct {'high-conf' if row['confidence_ml'] >= 70 else 'correct'}] {tech} -> {row['predicted_technique_ml']} ({row['confidence_ml']:.0f}%)")
            print(f"  {str(row['explanation_ml'])[:120]}...")
            print(f"  action={row['action']}")
    wrong = df[~df["is_correct_ml"]]
    if len(wrong) > 0:
        row = wrong.iloc[0]
        print(f"\n[Misclassified] true={row['technique_id']} pred={row['predicted_technique_ml']} ({row['confidence_ml']:.0f}%)")
        print(f"  {row['explanation_ml'][:120]}...")
        print(f"  action={row['action']}")

    return df


if __name__ == "__main__":
    run_improved_classification()
