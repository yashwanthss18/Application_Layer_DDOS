"""
Prediction Script
Purpose: Load trained model and make predictions on new user data
Can be integrated with Node.js backend via API or file-based interface
"""

import pandas as pd
import numpy as np
import joblib
import sys
import json
from datetime import datetime

# Configuration
MODEL_FILE = "model/isolation_forest.pkl"
SCALER_FILE = "model/scaler.pkl"

# Feature columns (must match training)
FEATURE_COLUMNS = [
    'uploads_per_time_window',
    'duplicate_file_ratio',
    'average_file_size',
    'upload_failure_rate',
    'max_file_size',
    'time_between_uploads_sec',
    'total_uploads',
    'total_bytes_uploaded',
    'ip_diversity',
    'unique_file_hashes'
]

# Risk thresholds (can be tuned based on false positive tolerance)
THRESHOLD_SUSPICIOUS = 0.65  # Moderate risk
THRESHOLD_MALICIOUS = 0.85   # High risk


def load_model_and_scaler():
    """Load trained model and scaler"""
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        return model, scaler
    except FileNotFoundError as e:
        print(f"Error: Model files not found: {e}")
        print("Please train the model first.")
        sys.exit(1)


def predict_single_user(user_features: dict) -> dict:
    """
    Predict risk level for a single user
    Args:
        user_features: Dictionary with feature names as keys
    Returns:
        Dictionary with risk assessment
    """
    model, scaler = load_model_and_scaler()

    # Validate features
    missing_features = [f for f in FEATURE_COLUMNS if f not in user_features]
    if missing_features:
        return {
            "status": "error",
            "message": f"Missing features: {missing_features}"
        }

    # Extract feature vector
    X = np.array([[user_features[f] for f in FEATURE_COLUMNS]])

    # Handle missing values
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)

    # Normalize
    X_scaled = scaler.transform(X)

    # Predict
    prediction = model.predict(X_scaled)[0]
    anomaly_score = -model.score_samples(X_scaled)[0]

    # Determine risk level
    if anomaly_score > THRESHOLD_MALICIOUS:
        risk_level = "MALICIOUS"
    elif anomaly_score > THRESHOLD_SUSPICIOUS:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "NORMAL"

    return {
        "status": "success",
        "anomaly_score": float(anomaly_score),
        "risk_level": risk_level,
        "is_anomaly": int(prediction == -1),
        "timestamp": datetime.utcnow().isoformat(),
        "thresholds": {
            "suspicious": THRESHOLD_SUSPICIOUS,
            "malicious": THRESHOLD_MALICIOUS
        }
    }


def predict_batch(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Predict risk for multiple users
    Args:
        features_df: DataFrame with features
    Returns:
        DataFrame with predictions and risk levels
    """
    model, scaler = load_model_and_scaler()

    X = features_df[FEATURE_COLUMNS].values
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
    X_scaled = scaler.transform(X)

    predictions = model.predict(X_scaled)
    anomaly_scores = -model.score_samples(X_scaled)

    # Determine risk levels
    risk_levels = []
    for score in anomaly_scores:
        if score > THRESHOLD_MALICIOUS:
            risk_levels.append("MALICIOUS")
        elif score > THRESHOLD_SUSPICIOUS:
            risk_levels.append("SUSPICIOUS")
        else:
            risk_levels.append("NORMAL")

    results_df = features_df[['user_id']].copy()
    results_df['anomaly_score'] = anomaly_scores
    results_df['risk_level'] = risk_levels
    results_df['is_anomaly'] = (predictions == -1).astype(int)

    return results_df


def main():
    """Demo: Run prediction on training data"""
    print("\n" + "="*60)
    print("Prediction Pipeline Demo")
    print("="*60)

    # Load and predict on training data
    try:
        training_preds = pd.read_csv("data/training_predictions.csv")
    except FileNotFoundError:
        print("Error: Training predictions file not found")
        return

    print(f"\nMaking predictions on {len(training_preds)} users...")
    batch_results = predict_batch(training_preds)

    # Show results
    print("\nPrediction Results:")
    print(batch_results.to_string())

    # Risk distribution
    print("\n" + "-"*60)
    print("Risk Distribution:")
    print(batch_results['risk_level'].value_counts())

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
