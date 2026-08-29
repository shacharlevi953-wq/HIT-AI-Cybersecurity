"""Phishing website detection demo for an introductory cybersecurity course.

The script trains and evaluates a Random Forest classifier on the UCI
"Phishing Websites" dataset (dataset id 327). It does not visit or execute
any URL; it only analyzes pre-extracted numeric features.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.io import arff
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split


RANDOM_STATE = 42
TARGET_CANDIDATES = {"result", "class", "label", "target"}


def _decode(value):
    return value.decode("utf-8") if isinstance(value, bytes) else value


def load_uci_arff(path: Path) -> tuple[pd.DataFrame, pd.Series]:
    """Load UCI ARFF and return X plus binary y (1=phishing, 0=legitimate)."""
    raw, _ = arff.loadarff(path)
    frame = pd.DataFrame(raw).map(_decode)
    target_column = next(
        (c for c in frame.columns if c.strip().lower() in TARGET_CANDIDATES),
        frame.columns[-1],
    )
    y_raw = pd.to_numeric(frame.pop(target_column), errors="raise")
    X = frame.apply(pd.to_numeric, errors="raise")

    # In UCI dataset 327: -1 denotes phishing and +1 denotes legitimate.
    y = (y_raw == -1).astype(int)
    y.name = "is_phishing"
    return X, y


def save_confusion_matrix(y_true, y_pred, output_dir: Path) -> None:
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6.2, 5.2))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        cbar=False,
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
    )
    plt.title("Confusion Matrix - Test Set")
    plt.xlabel("Predicted class")
    plt.ylabel("Actual class")
    plt.tight_layout()
    plt.savefig(output_dir / "confusion_matrix.png", dpi=180)
    plt.close()


def save_roc(y_true, probabilities, output_dir: Path) -> float:
    fpr, tpr, _ = roc_curve(y_true, probabilities)
    auc = roc_auc_score(y_true, probabilities)
    plt.figure(figsize=(6.2, 5.2))
    plt.plot(fpr, tpr, linewidth=2.5, label=f"Random Forest (AUC={auc:.3f})")
    plt.plot([0, 1], [0, 1], "--", color="gray", label="Random baseline")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve - Phishing Detection")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(output_dir / "roc_curve.png", dpi=180)
    plt.close()
    return float(auc)


def save_feature_importance(model, X_test, y_test, output_dir: Path) -> pd.DataFrame:
    result = permutation_importance(
        model,
        X_test,
        y_test,
        scoring="f1",
        n_repeats=8,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    importance = (
        pd.DataFrame(
            {
                "feature": X_test.columns,
                "importance_mean": result.importances_mean,
                "importance_std": result.importances_std,
            }
        )
        .sort_values("importance_mean", ascending=False)
        .reset_index(drop=True)
    )
    top = importance.head(10).sort_values("importance_mean")
    plt.figure(figsize=(8.3, 5.5))
    plt.barh(
        top["feature"],
        top["importance_mean"],
        xerr=top["importance_std"],
        color="#2f6b9a",
        alpha=0.9,
    )
    plt.xlabel("Mean decrease in test F1 after permutation")
    plt.title("Explainable AI: Top Features")
    plt.grid(axis="x", alpha=0.25)
    plt.tight_layout()
    plt.savefig(output_dir / "feature_importance.png", dpi=180)
    plt.close()
    importance.to_csv(output_dir / "feature_importance.csv", index=False)
    return importance


def build_alerts(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    predictions: np.ndarray,
    probabilities: np.ndarray,
    importance: pd.DataFrame,
) -> pd.DataFrame:
    top_features = importance.head(5)["feature"].tolist()
    alerts = X_test.loc[:, top_features].copy()
    alerts.insert(0, "record_id", X_test.index.astype(str))
    alerts["actual_is_phishing"] = y_test.to_numpy()
    alerts["predicted_is_phishing"] = predictions
    alerts["phishing_probability"] = probabilities.round(4)
    alerts["mitre_tactic"] = "Initial Access"
    alerts["mitre_technique"] = "T1566.002 - Spearphishing Link"
    alerts["recommended_action"] = np.where(
        probabilities >= 0.80,
        "Block and investigate",
        np.where(probabilities >= 0.50, "Quarantine for analyst review", "Allow"),
    )
    return alerts.sort_values("phishing_probability", ascending=False).head(20)


def run(data_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    X, y = load_uci_arff(data_path)
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        stratify=y,
        random_state=RANDOM_STATE,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, 1]

    save_confusion_matrix(y_test, predictions, output_dir)
    auc = save_roc(y_test, probabilities, output_dir)
    importance = save_feature_importance(model, X_test, y_test, output_dir)
    alerts = build_alerts(
        X_test, y_test, predictions, probabilities, importance
    )
    alerts.to_csv(output_dir / "sample_soc_alerts.csv", index=False)

    cm = confusion_matrix(y_test, predictions)
    metrics = {
        "dataset": "UCI Phishing Websites (id=327)",
        "instances": int(len(X)),
        "features": int(X.shape[1]),
        "train_instances": int(len(X_train)),
        "test_instances": int(len(X_test)),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_phishing": float(precision_score(y_test, predictions)),
        "recall_phishing": float(recall_score(y_test, predictions)),
        "f1_phishing": float(f1_score(y_test, predictions)),
        "roc_auc": auc,
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            target_names=["legitimate", "phishing"],
            output_dict=True,
        ),
        "top_10_features": importance.head(10).to_dict(orient="records"),
        "random_state": RANDOM_STATE,
    }
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("data/Training Dataset.arff"),
        help="Path to the UCI ARFF dataset",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results"),
        help="Directory for metrics, charts, and sample SOC alerts",
    )
    args = parser.parse_args()
    metrics = run(args.data, args.output_dir)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
