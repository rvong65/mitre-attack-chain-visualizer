"""
Balanced classification with SMOTE: resampling on train only, RF/ET with class_weight.
Targets macro-F1 >0.50, balanced acc >0.50. Resampling on train only; model lightweight
(<200MB serialized est.), suitable for Streamlit @st.cache_resource.
"""
from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder

from ..config import PROCESSED_DIR, PROJECT_ROOT

# Reuse feature set; load_and_prepare will try classified_improved first
from .improved import load_and_prepare

MODELS_DIR = PROJECT_ROOT / "models"
DT_BASELINE_ACC = 0.6063
VOTING_ACC = 0.4194
PREV_MACRO_F1 = 0.29


def build_pipeline(sampler, classifier):
    """Return imblearn Pipeline with resample + clf. Predict uses only clf (no test leakage)."""
    from imblearn.pipeline import Pipeline as ImbPipeline
    return ImbPipeline(steps=[("resample", sampler), ("clf", classifier)])


def train_balanced(X_train, y_train, random_state: int = 42):
    """
    Build RF and ET pipelines with SMOTE; 5-fold CV f1_macro; fit best; return (pipeline, name, cv_score).
    If SMOTE fails (e.g. class with <6 samples), fall back to RandomOverSampler.
    """
    from imblearn.over_sampling import RandomOverSampler, SMOTE

    smote = SMOTE(k_neighbors=5, random_state=random_state)
    ros = RandomOverSampler(random_state=random_state)

    rf = RandomForestClassifier(
        n_estimators=180,
        max_depth=14,
        min_samples_leaf=8,
        class_weight="balanced_subsample",
        random_state=random_state,
    )
    et = ExtraTreesClassifier(
        n_estimators=180,
        max_depth=14,
        min_samples_leaf=8,
        class_weight="balanced_subsample",
        random_state=random_state,
    )

    candidates = [
        ("RF_SMOTE", smote, rf),
        ("ET_SMOTE", smote, et),
    ]
    best_pipeline = None
    best_name = None
    best_score = -1

    for name, resampler, clf in candidates:
        pipe = build_pipeline(resampler, clf)
        try:
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                scores = cross_val_score(
                    pipe, X_train, y_train, cv=5, scoring="f1_macro", n_jobs=-1
                )
            if w:
                for warning in w:
                    print(f"  [SMOTE/CV] {warning.message}")
        except (ValueError, Exception) as e:
            # SMOTE can fail if a class has fewer than k_neighbors+1 samples
            print(f"  {name} failed ({e}), trying RandomOverSampler")
            pipe = build_pipeline(ros, clf)
            scores = cross_val_score(
                pipe, X_train, y_train, cv=5, scoring="f1_macro", n_jobs=-1
            )
        mean_score = scores.mean()
        if mean_score > best_score:
            best_score = mean_score
            best_name = name
            best_pipeline = pipe

    best_pipeline.fit(X_train, y_train)
    return best_pipeline, best_name, best_score


def _get_importances(pipeline):
    """Feature importances from pipeline's clf step."""
    clf = pipeline.named_steps.get("clf")
    if clf is not None and hasattr(clf, "feature_importances_"):
        return clf.feature_importances_
    return None


def predict_with_explain(pipeline, X, feature_names, le, top_k: int = 3):
    """Predict labels, proba; build explanation from clf feature importances. Return pred_labels, confidence_ml, explanation_ml."""
    proba = pipeline.predict_proba(X)
    pred_enc = proba.argmax(axis=1)
    pred_proba_max = proba.max(axis=1)
    pred_labels = le.inverse_transform(pred_enc)

    importances = _get_importances(pipeline)
    if importances is None:
        importances = np.zeros(len(feature_names))
    imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=False)
    top_features = imp_series.head(top_k)

    explanations = []
    for i in range(len(X)):
        pred_id = pred_labels[i]
        conf = pred_proba_max[i] * 100
        parts = [f"{feat} (imp {imp_series[feat]:.2f})" for feat in top_features.index]
        expl = f"Predicted {pred_id} ({conf:.0f}%): Top contributors - {', '.join(parts)}."
        explanations.append(expl)
    return pred_labels, pred_proba_max * 100, explanations


def add_confidence_gate(confidence_ml: float) -> str:
    """Return action: Auto-Classify >=80, Review 50-80, Low Conf/Unknown <50."""
    if confidence_ml >= 80:
        return "Auto-Classify"
    if confidence_ml >= 50:
        return "Review"
    return "Low Conf/Unknown"


def evaluate_and_compare(y_test, y_pred, le, prev_dt_acc=DT_BASELINE_ACC, prev_voting_acc=VOTING_ACC):
    """Print report, confusion matrix, balanced acc, accuracy, macro-F1 lift vs previous."""
    y_test_str = le.inverse_transform(y_test)
    y_pred_str = le.inverse_transform(y_pred)

    acc = accuracy_score(y_test, y_pred)
    bal_acc = balanced_accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    print("\n--- Classification report ---")
    print(classification_report(y_test_str, y_pred_str, zero_division=0))
    print("--- Confusion matrix ---")
    print(confusion_matrix(y_test_str, y_pred_str))
    print(pd.crosstab(y_test_str, y_pred_str, margins=True))
    print(f"\nAccuracy: {acc:.2%}  Balanced accuracy: {bal_acc:.2%}  Macro F1: {macro_f1:.3f}")
    print(f"\n--- Comparison vs previous ---")
    print(f"  DT baseline (in-sample): {prev_dt_acc:.2%}")
    print(f"  Voting (test):           {prev_voting_acc:.2%}")
    print(f"  Balanced (this run):     {acc:.2%}  (balanced acc {bal_acc:.2%})")
    print(f"  Macro-F1 lift vs 0.29:   {macro_f1 - PREV_MACRO_F1:+.3f} (current {macro_f1:.3f})")
    return {"accuracy": acc, "balanced_accuracy": bal_acc, "macro_f1": macro_f1}


def run_balanced_classification(csv_path=None):
    """
    Load (prefer classified_improved.csv), split, train_balanced, evaluate, save pipeline + encoder
    + test_predictions_balanced.csv + full classified_balanced_full.csv + importances plot.
    """
    path = csv_path or PROCESSED_DIR / "classified_improved.csv"
    if not path.exists():
        path = PROCESSED_DIR / "classified_events.csv"
    if not path.exists():
        path = PROCESSED_DIR / "combined_features.csv"
    if not path.exists():
        raise FileNotFoundError(f"No data at {PROCESSED_DIR}")

    X, y, df, feature_names, le = load_and_prepare(path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    with warnings.catch_warnings(record=True) as smote_warnings:
        warnings.simplefilter("always")
        pipeline, best_name, cv_score = train_balanced(X_train, y_train)
    if smote_warnings:
        print("\n--- SMOTE / resampler warnings ---")
        for w in smote_warnings:
            print(f"  {w.message}")

    print(f"\nBest pipeline: {best_name} (cv f1_macro={cv_score:.3f})")

    # Predict on test
    y_pred_test = pipeline.predict(X_test)
    y_proba_test = pipeline.predict_proba(X_test)
    pred_labels_test, confidence_test, explanation_test = predict_with_explain(
        pipeline, X_test, feature_names, le
    )
    metrics = evaluate_and_compare(y_test, y_pred_test, le)

    # Test DF: rows corresponding to test set (X shares index with df from load_and_prepare)
    test_df = df.loc[X_test.index].copy().reset_index(drop=True)
    test_df["predicted_technique_ml"] = pred_labels_test
    test_df["confidence_ml"] = confidence_test
    test_df["explanation_ml"] = explanation_test
    test_df["action"] = test_df["confidence_ml"].map(add_confidence_gate)
    test_df["is_correct_ml"] = test_df["predicted_technique_ml"] == test_df["technique_id"]
    if "predicted_technique" in test_df.columns:
        def append_rule(row):
            if row["predicted_technique"] == row["predicted_technique_ml"] and pd.notna(row.get("predicted_technique")):
                return row["explanation_ml"] + f" Rule agreed: {row['predicted_technique']}."
            return row["explanation_ml"]
        test_df["explanation_ml"] = test_df.apply(append_rule, axis=1)

    out_test = PROCESSED_DIR / "test_predictions_balanced.csv"
    test_df.to_csv(out_test, index=False)
    print(f"\nTest predictions saved to {out_test}")

    # Full DF predictions
    pred_labels_full, confidence_full, explanation_full = predict_with_explain(
        pipeline, X, feature_names, le
    )
    df_full = df.copy()
    df_full["predicted_technique_ml"] = pred_labels_full
    df_full["confidence_ml"] = confidence_full
    df_full["explanation_ml"] = explanation_full
    df_full["action"] = df_full["confidence_ml"].map(add_confidence_gate)
    df_full["is_correct_ml"] = df_full["predicted_technique_ml"] == df_full["technique_id"]
    if "predicted_technique" in df_full.columns:
        def append_rule_full(row):
            if row["predicted_technique"] == row["predicted_technique_ml"] and pd.notna(row.get("predicted_technique")):
                return row["explanation_ml"] + f" Rule agreed: {row['predicted_technique']}."
            return row["explanation_ml"]
        df_full["explanation_ml"] = df_full.apply(append_rule_full, axis=1)
    out_full = PROCESSED_DIR / "classified_balanced_full.csv"
    df_full.to_csv(out_full, index=False)
    print(f"Full predictions saved to {out_full}")

    # Feature importances plot (top 15)
    importances = _get_importances(pipeline)
    if importances is not None:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=False).head(15).iloc[::-1]
            fig, ax = plt.subplots(figsize=(8, 6))
            imp_series.plot.barh(ax=ax)
            ax.set_title("Top 15 feature importances (balanced)")
            ax.set_xlabel("Importance")
            plt.tight_layout()
            plot_path = PROCESSED_DIR / "feature_importances_balanced.png"
            plt.savefig(plot_path, dpi=100)
            plt.close()
            print(f"\nFeature importances plot saved to {plot_path}")
        except Exception as e:
            print(f"Could not save importances plot: {e}")
        print("\nTop 15 feature importances:")
        imp_series = pd.Series(importances, index=feature_names).sort_values(ascending=False)
        for feat, val in imp_series.head(15).items():
            print(f"  {feat}: {val:.3f}")

    # Save model and encoder
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODELS_DIR / "best_rf_balanced.joblib", compress=3)
    joblib.dump(le, MODELS_DIR / "label_encoder_balanced.joblib", compress=3)
    print(f"Model saved to {MODELS_DIR / 'best_rf_balanced.joblib'}")

    # Sample 5 rows: high-conf correct per class + one misclassified/low-conf
    print("\n--- Sample rows (high-conf correct + misclassified/low-conf) ---")
    for tech in sorted(df_full["technique_id"].unique()):
        subset = df_full[df_full["technique_id"] == tech]
        correct_high = subset[subset["is_correct_ml"] & (subset["confidence_ml"] >= 70)]
        if len(correct_high) == 0:
            correct_high = subset[subset["is_correct_ml"]]
        if len(correct_high) > 0:
            row = correct_high.iloc[0]
            label = "high-conf" if row["confidence_ml"] >= 70 else "correct"
            print(f"\n[Correct {label}] {tech} -> {row['predicted_technique_ml']} ({row['confidence_ml']:.0f}%)")
            print(f"  {str(row['explanation_ml'])[:100]}...")
            print(f"  action={row['action']}")
    wrong = df_full[~df_full["is_correct_ml"]]
    if len(wrong) > 0:
        row = wrong.iloc[0]
        print(f"\n[Misclassified] true={row['technique_id']} pred={row['predicted_technique_ml']} ({row['confidence_ml']:.0f}%)")
        print(f"  {str(row['explanation_ml'])[:100]}...")
        print(f"  action={row['action']}")

    return df_full


if __name__ == "__main__":
    run_balanced_classification()
