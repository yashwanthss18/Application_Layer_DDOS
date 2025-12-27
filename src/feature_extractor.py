"""
Feature Extractor
Purpose: Extract ML features from raw upload logs
Features computed:
- uploads_per_time_window: Number of uploads in rolling 5-minute windows
- duplicate_file_ratio: Proportion of duplicate file hashes
- average_file_size: Mean file size in bytes
- upload_failure_rate: Ratio of failed uploads
- max_file_size: Largest file uploaded
- time_between_uploads: Average time between consecutive uploads
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os

# Configuration
LOG_FILE = "data/upload_logs.csv"
FEATURES_FILE = "data/extracted_features.csv"
TIME_WINDOW_MINUTES = 5
MIN_UPLOADS_PER_USER = 2  # Filter out users with too few uploads


def load_and_parse_logs(log_file: str) -> pd.DataFrame:
    """Load upload logs and parse timestamps"""
    df = pd.read_csv(log_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')
    return df


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features for each user from upload logs
    Returns dataframe with one row per user containing all features
    """
    features_list = []

    for user_id in df['user_id'].unique():
        user_data = df[df['user_id'] == user_id].copy()

        # Skip users with minimal activity
        if len(user_data) < MIN_UPLOADS_PER_USER:
            continue

        # 1. Uploads per time window (5-minute rolling window)
        uploads_per_window = compute_uploads_per_window(user_data, TIME_WINDOW_MINUTES)

        # 2. Duplicate file ratio
        duplicate_ratio = compute_duplicate_ratio(user_data)

        # 3. Average file size
        avg_file_size = user_data[user_data['success'] == 1]['file_size'].mean()
        avg_file_size = avg_file_size if not np.isnan(avg_file_size) else 0

        # 4. Upload failure rate
        failure_rate = compute_failure_rate(user_data)

        # 5. Max file size
        max_file_size = user_data[user_data['success'] == 1]['file_size'].max()
        max_file_size = max_file_size if not np.isnan(max_file_size) else 0

        # 6. Time between uploads (seconds)
        time_between = compute_time_between_uploads(user_data)

        # 7. Total upload count
        total_uploads = len(user_data)

        # 8. Total bytes uploaded
        total_bytes = user_data[user_data['success'] == 1]['file_size'].sum()

        # 9. IP diversity (how many different IPs this user used)
        ip_diversity = user_data['ip_address'].nunique()

        # 10. Unique file hashes (indicator of variety vs. duplicates)
        unique_hashes = user_data['file_hash'].nunique()

        # Determine user label (normal vs. attack)
        user_label = determine_user_label(user_data, duplicate_ratio, uploads_per_window)

        features_list.append({
            'user_id': user_id,
            'uploads_per_time_window': uploads_per_window,
            'duplicate_file_ratio': duplicate_ratio,
            'average_file_size': avg_file_size,
            'upload_failure_rate': failure_rate,
            'max_file_size': max_file_size,
            'time_between_uploads_sec': time_between,
            'total_uploads': total_uploads,
            'total_bytes_uploaded': total_bytes,
            'ip_diversity': ip_diversity,
            'unique_file_hashes': unique_hashes,
            'label': user_label  # For validation: 0=normal, 1=attack
        })

    return pd.DataFrame(features_list)


def compute_uploads_per_window(user_data: pd.DataFrame, window_minutes: int) -> float:
    """
    Compute the maximum number of uploads in any time window
    High values indicate potential upload flooding
    """
    if len(user_data) < 2:
        return 0

    user_data = user_data.sort_values('timestamp')
    timestamps = user_data['timestamp'].values
    max_uploads = 0

    for i in range(len(timestamps)):
        window_end = timestamps[i] + np.timedelta64(window_minutes, 'm')
        uploads_in_window = sum((timestamps >= timestamps[i]) & (timestamps <= window_end))
        max_uploads = max(max_uploads, uploads_in_window)

    return float(max_uploads)


def compute_duplicate_ratio(user_data: pd.DataFrame) -> float:
    """
    Compute the ratio of duplicate file hashes
    High values indicate repeated uploads of same file
    """
    successful_uploads = user_data[user_data['success'] == 1]

    if len(successful_uploads) == 0:
        return 0

    hashes = successful_uploads['file_hash'].dropna()
    if len(hashes) == 0:
        return 0

    unique_hashes = hashes.nunique()
    duplicate_count = len(hashes) - unique_hashes

    return float(duplicate_count / len(hashes)) if len(hashes) > 0 else 0


def compute_failure_rate(user_data: pd.DataFrame) -> float:
    """
    Compute the ratio of failed uploads
    Moderate values might indicate misconfiguration or attacks
    """
    total = len(user_data)
    if total == 0:
        return 0

    failed = (user_data['success'] == 0).sum()
    return float(failed / total)


def compute_time_between_uploads(user_data: pd.DataFrame) -> float:
    """
    Compute average time between consecutive uploads (in seconds)
    Low values indicate rapid-fire uploads (potential flooding)
    """
    if len(user_data) < 2:
        return 0

    user_data = user_data.sort_values('timestamp')
    timestamps = user_data['timestamp'].values

    if len(timestamps) < 2:
        return 0

    time_diffs = np.diff(timestamps)
    # Convert timedelta to seconds
    time_diffs_sec = np.array([td / np.timedelta64(1, 's') for td in time_diffs])

    return float(np.mean(time_diffs_sec)) if len(time_diffs_sec) > 0 else 0


def determine_user_label(user_data: pd.DataFrame, dup_ratio: float, uploads_per_window: float) -> int:
    """
    Heuristic labeling for validation purposes
    0 = normal user, 1 = likely attacker
    Used to validate model performance
    """
    # Check if user_id contains "attacker"
    user_id = user_data['user_id'].iloc[0]

    if "attacker" in user_id.lower():
        return 1
    return 0


def main():
    """Main extraction pipeline"""
    print("\n" + "="*60)
    print("Feature Extraction Pipeline")
    print("="*60)

    if not os.path.exists(LOG_FILE):
        print(f"Error: Log file not found: {LOG_FILE}")
        print("Please run the simulator first.")
        return

    print("Loading upload logs...")
    df = load_and_parse_logs(LOG_FILE)
    print(f"Loaded {len(df)} upload records for {df['user_id'].nunique()} users")

    print("Extracting features...")
    features_df = extract_features(df)
    print(f"Extracted features for {len(features_df)} users")

    # Save features
    os.makedirs("data", exist_ok=True)
    features_df.to_csv(FEATURES_FILE, index=False)
    print(f"\nFeatures saved to: {FEATURES_FILE}")

    # Display statistics
    print("\nFeature Statistics (Normal Users):")
    normal_users = features_df[features_df['label'] == 0]
    print(f"  Uploads per window: mean={normal_users['uploads_per_time_window'].mean():.2f}, "
          f"std={normal_users['uploads_per_time_window'].std():.2f}")
    print(f"  Duplicate ratio: mean={normal_users['duplicate_file_ratio'].mean():.3f}, "
          f"std={normal_users['duplicate_file_ratio'].std():.3f}")
    print(f"  Avg file size (KB): mean={normal_users['average_file_size'].mean()/1024:.2f}, "
          f"std={normal_users['average_file_size'].std()/1024:.2f}")

    print("\nFeature Statistics (Attack Users):")
    attack_users = features_df[features_df['label'] == 1]
    print(f"  Uploads per window: mean={attack_users['uploads_per_time_window'].mean():.2f}, "
          f"std={attack_users['uploads_per_time_window'].std():.2f}")
    print(f"  Duplicate ratio: mean={attack_users['duplicate_file_ratio'].mean():.3f}, "
          f"std={attack_users['duplicate_file_ratio'].std():.3f}")
    print(f"  Avg file size (KB): mean={attack_users['average_file_size'].mean()/1024:.2f}, "
          f"std={attack_users['average_file_size'].std()/1024:.2f}")

    print("="*60 + "\n")


if __name__ == "__main__":
    main()
