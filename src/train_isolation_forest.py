"""
Isolation Forest Training
Purpose: Train the Isolation Forest model on extracted features
Why Isolation Forest:
- Unsupervised learning (works without labeled attack data)
- Excellent for high-dimensional anomaly detection
- Naturally handles multivariate outliers
- Fast and scalable
- Provides anomaly scores (0-1) instead of binary decisions
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

# Configuration
FEATURES_FILE = "data/extracted_features.csv"
MODEL_FILE = "model/isolation_forest.pkl"
SCALER_FILE = "model/scaler.pkl"

# Feature columns to use
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

# Isolation Forest hyperparameters
CONTAMINATION = 0.1  # Assume 10% of data might be anomalies
RANDOM_STATE = 42
N_ESTIMATORS = 100


def load_features(features_file: str) -> pd.DataFrame:
    """Load extracted features"""
    return pd.read_csv(features_file)


def normalize_features(X: np.ndarray) -> tuple:
    """Normalize features using StandardScaler"""
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, scaler


def train_isolation_forest(X: np.ndarray) -> IsolationForest:
    """Train Isolation Forest model"""
    model = IsolationForest(
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_estimators=N_ESTIMATORS,
        n_jobs=-1  # Use all available cores
    )
    model.fit(X)
    return model


def main():
    """Main training pipeline"""
    print("\n" + "="*60)
    print("Isolation Forest Model Training")
    print("="*60)

    # Load features
    if not os.path.exists(FEATURES_FILE):
        print(f"Error: Features file not found: {FEATURES_FILE}")
        print("Please run feature extraction first.")
        return

    print(f"Loading features from {FEATURES_FILE}...")
    df = load_features(FEATURES_FILE)
    print(f"Loaded features for {len(df)} users")

    # Extract feature matrix
    print(f"\nUsing {len(FEATURE_COLUMNS)} features:")
    for col in FEATURE_COLUMNS:
        print(f"  - {col}")

    X = df[FEATURE_COLUMNS].values

    # Handle missing values
    X = np.nan_to_num(X, nan=0, posinf=0, neginf=0)
    print(f"\nFeature matrix shape: {X.shape}")

    # Normalize features
    print("\nNormalizing features...")
    X_scaled, scaler = normalize_features(X)

    # Train model
    print("Training Isolation Forest model...")
    model = train_isolation_forest(X_scaled)

    # Save model and scaler
    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    print(f"\nModel saved to: {MODEL_FILE}")
    print(f"Scaler saved to: {SCALER_FILE}")

    # Compute anomaly scores
    print("\nComputing anomaly scores...")
    anomaly_scores = -model.score_samples(X_scaled)  # Convert to positive scores
    df['anomaly_score'] = anomaly_scores

    # Predictions (-1 = anomaly, 1 = normal)
    predictions = model.predict(X_scaled)
    df['prediction'] = predictions

    # Save predictions
    df.to_csv("data/training_predictions.csv", index=False)
    print("Predictions saved to: data/training_predictions.csv")

    # Model insights
    print("\n" + "="*60)
    print("MODEL INSIGHTS")
    print("="*60)

    print(f"\nAnomalies detected: {(predictions == -1).sum()} out of {len(df)} users")
    print(f"Normal users: {(predictions == 1).sum()}")

    print("\nAnomaly Score Statistics:")
    print(f"  Min: {anomaly_scores.min():.4f}")
    print(f"  Max: {anomaly_scores.max():.4f}")
    print(f"  Mean: {anomaly_scores.mean():.4f}")
    print(f"  Std: {anomaly_scores.std():.4f}")

    # Percentiles for threshold determination
    print("\nAnomaly Score Percentiles:")
    for percentile in [25, 50, 75, 90, 95, 99]:
        value = np.percentile(anomaly_scores, percentile)
        print(f"  {percentile}th percentile: {value:.4f}")

    print("\nSuggested Thresholds:")
    print(f"  Normal (safe): < {np.percentile(anomaly_scores, 75):.4f}")
    print(f"  Suspicious: {np.percentile(anomaly_scores, 75):.4f} - {np.percentile(anomaly_scores, 95):.4f}")
    print(f"  Malicious (alert): > {np.percentile(anomaly_scores, 95):.4f}")

    # Analysis by label
    print("\nPerformance by User Type:")
    for label in [0, 1]:
        label_name = "Normal" if label == 0 else "Attack"
        label_mask = df['label'] == label
        label_preds = predictions[label_mask]
        accuracy = ((label_preds == -1) if label == 1 else (label_preds == 1)).mean()
        print(f"  {label_name} users correctly identified: {accuracy*100:.1f}%")

    print("="*60 + "\n")


if __name__ == "__main__":
    main()
