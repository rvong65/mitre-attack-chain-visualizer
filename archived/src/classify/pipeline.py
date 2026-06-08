"""
Classification pipeline: apply rules, evaluate, save classified_events.csv.
"""
import pandas as pd

from ..config import PROCESSED_DIR
from .explainer import generate_explanation
from .load import load_features
from .scorer import score_technique


def apply_rules(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply rule-based classification to each row.
    Adds predicted_technique, confidence_score, explanation.
    """
    if df.empty:
        df = df.copy()
        df["predicted_technique"] = []
        df["confidence_score"] = []
        df["explanation"] = []
        return df

    predicted = []
    scores = []
    explanations = []

    for _, row in df.iterrows():
        tech, conf, reasons = score_technique(row.to_dict())
        predicted.append(tech)
        scores.append(conf)
        explanations.append(generate_explanation(tech, conf, reasons))

    df = df.copy()
    df["predicted_technique"] = predicted
    df["confidence_score"] = scores
    df["explanation"] = explanations

    return df


def run_classification(prefer_parquet: bool = False) -> pd.DataFrame:
    """
    Load features, apply rules, add is_correct, print evaluation, save classified_events.csv.
    Prints: overall accuracy, per-technique breakdown, precision/recall/F1,
    sample FP/FN, 3-5 example rows (one per technique + one misclassified).
    """
    df = load_features(prefer_parquet=prefer_parquet)
    if df.empty:
        print("No features to classify.")
        return df

    df = apply_rules(df)

    # is_correct: compare to ground truth
    if "technique_id" in df.columns:
        df["is_correct"] = df["predicted_technique"] == df["technique_id"]
    else:
        df["is_correct"] = pd.NA

    # Save
    out_path = PROCESSED_DIR / "classified_events.csv"
    df.to_csv(out_path, index=False)
    print(f"Saved to {out_path} ({len(df)} rows)")

    # Evaluation
    if "technique_id" in df.columns and "is_correct" in df.columns:
        overall_acc = df["is_correct"].mean()
        _print_evaluation(df)
        _print_example_rows(df)

        # Optional: DecisionTree baseline if rule accuracy < 80%
        if overall_acc < 0.80:
            try:
                from .baseline_ml import run_baseline_ml

                run_baseline_ml(df, overall_acc)
            except ImportError:
                print("\n(sklearn not installed; skipping ML baseline)")

    return df


def _print_evaluation(df: pd.DataFrame) -> None:
    """Print accuracy, per-technique, precision/recall/F1, FP/FN samples."""
    correct = df["is_correct"].sum()
    total = len(df)
    overall_acc = correct / total if total else 0
    print(f"\n--- Overall accuracy: {overall_acc:.2%} ({correct}/{total}) ---")

    # Crosstab
    print("\n--- Confusion-style (technique_id vs predicted_technique) ---")
    ct = pd.crosstab(df["technique_id"], df["predicted_technique"], margins=True)
    print(ct)

    # Per-technique precision/recall/F1
    print("\n--- Per-technique precision / recall / F1 ---")
    techniques = df["technique_id"].unique()
    for tech in sorted(techniques):
        actual_pos = df["technique_id"] == tech
        pred_pos = df["predicted_technique"] == tech
        tp = (actual_pos & pred_pos).sum()
        fp = (~actual_pos & pred_pos).sum()
        fn = (actual_pos & ~pred_pos).sum()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        acc_tech = (df.loc[actual_pos, "is_correct"]).sum() / max(actual_pos.sum(), 1)
        print(f"  {tech}: precision={prec:.2%} recall={rec:.2%} F1={f1:.2%} (accuracy on class)={acc_tech:.2%}")

    # FP/FN samples
    wrong = df[~df["is_correct"]]
    if len(wrong) > 0:
        print("\n--- Sample false positives/negatives (up to 10) ---")
        sample = wrong.head(10)
        cols = ["technique_id", "predicted_technique", "confidence_score", "explanation"]
        cols = [c for c in cols if c in sample.columns]
        print(sample[cols].to_string())


def _print_example_rows(df: pd.DataFrame) -> None:
    """Print 3-5 example rows: one per technique + one misclassified."""
    print("\n--- Example rows (one per technique + one misclassified) ---")
    # Prefer a correct example per technique when available, else first row
    for tech in sorted(df["technique_id"].unique()):
        subset = df[df["technique_id"] == tech]
        if len(subset) == 0:
            continue
        correct_subset = subset[subset["is_correct"]]
        row = correct_subset.iloc[0] if len(correct_subset) > 0 else subset.iloc[0]
        expl = str(row["explanation"])
        if len(expl) > 150:
            expl = expl[:150] + "..."
        print(f"\n[{tech}] (correct={row['is_correct']})")
        print(f"  predicted={row['predicted_technique']} conf={row['confidence_score']}%")
        print(f"  explanation: {expl}")

    # One misclassified (distinct from above)
    wrong = df[~df["is_correct"]]
    if len(wrong) > 0:
        row = wrong.iloc[0]
        expl = str(row["explanation"])
        if len(expl) > 150:
            expl = expl[:150] + "..."
        print(f"\n[Misclassified] (true={row['technique_id']}, pred={row['predicted_technique']})")
        print(f"  confidence={row['confidence_score']}%")
        print(f"  explanation: {expl}")
