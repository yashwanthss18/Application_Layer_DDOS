"""
Model Evaluation
Purpose: Evaluate Isolation Forest performance on test data
Metrics: Precision, Recall, F1-Score, ROC-AUC
Visualizations: Confusion Matrix, Feature Importance
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import (
    confusion_matrix, classification_report, roc_auc_score,
    roc_curve, auc
)

# Configuration
PREDICTIONS_FILE = "data/training_predictions.csv"
MODEL_FILE = "model/isolation_forest.pkl"
SCALER_FILE = "model/scaler.pkl"


def load_predictions(predictions_file: str) -> pd.DataFrame:
    """Load predictions and labels"""
    return pd.read_csv(predictions_file)


def load_model(model_file: str):
    """Load trained model"""
    return joblib.load(model_file)


def evaluate_model(df: pd.DataFrame):
    """Evaluate model performance"""
    # Ground truth labels (0=normal, 1=attack)
    y_true = df['label'].values

    # Model predictions (-1=anomaly/attack, 1=normal)
    # Convert to binary: 1=anomaly, 0=normal
    y_pred = (df['prediction'] == -1).astype(int)

    # Anomaly scores (higher = more anomalous)
    y_scores = df['anomaly_score'].values

    print("\n" + "="*60)
    print("MODEL EVALUATION RESULTS")
    print("="*60)

    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    print("\nConfusion Matrix:")
    print(f"  True Negatives:  {cm[0,0]}")
    print(f"  False Positives: {cm[0,1]}")
    print(f"  False Negatives: {cm[1,0]}")
    print(f"  True Positives:  {cm[1,1]}")

    # Classification Report
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=['Normal', 'Attack']))

    # ROC-AUC
    try:
        roc_auc = roc_auc_score(y_true, y_scores)
        print(f"ROC-AUC Score: {roc_auc:.4f}")
    except Exception as e:
        print(f"ROC-AUC Score: Cannot compute ({str(e)})")

    # Additional metrics
    tn, fp, fn, tp = cm.ravel()

    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = sensitivity

    print(f"\nAdditional Metrics:")
    print(f"  Sensitivity (Recall): {sensitivity:.4f}")
    print(f"  Specificity: {specificity:.4f}")
    print(f"  Precision: {precision:.4f}")

    print("="*60 + "\n")


def main():
    """Main evaluation pipeline"""
    print("\n" + "="*60)
    print("Model Evaluation Pipeline")
    print("="*60)

    # Load predictions
    if not os.path.exists(PREDICTIONS_FILE):
        print(f"Error: Predictions file not found: {PREDICTIONS_FILE}")
        print("Please train the model first.")
        return

    print(f"Loading predictions from {PREDICTIONS_FILE}...")
    df = load_predictions(PREDICTIONS_FILE)

    print(f"Loaded {len(df)} predictions")

    # Evaluate
    evaluate_model(df)

    # Show some high-risk users
    print("Top 10 Most Anomalous Users:")
    print("-" * 60)
    top_anomalies = df.nlargest(10, 'anomaly_score')[
        ['user_id', 'anomaly_score', 'uploads_per_time_window',
         'duplicate_file_ratio', 'label', 'prediction']
    ]

    for idx, row in top_anomalies.iterrows():
        label_name = "Attack" if row['label'] == 1 else "Normal"
        pred_name = "Anomaly" if row['prediction'] == -1 else "Normal"
        print(f"\nUser: {row['user_id']}")
        print(f"  Score: {row['anomaly_score']:.4f}")
        print(f"  Uploads/window: {row['uploads_per_time_window']:.1f}")
        print(f"  Dup ratio: {row['duplicate_file_ratio']:.3f}")
        print(f"  True Label: {label_name}")
        print(f"  Prediction: {pred_name}")

    print("\n" + "="*60)


if __name__ == "__main__":
    main()
