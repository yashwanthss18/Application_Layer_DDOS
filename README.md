# CloudDrive ML Security - DDoS/Abuse Detection System

## Project Overview

This is a complete, production-grade ML-based anomaly detection system designed to detect DDoS and abuse patterns in file upload services. The system uses **Isolation Forest**, an unsupervised machine learning algorithm, to identify suspicious user behavior without requiring labeled attack data.

### Key Features

- **No labeled data required**: Uses unsupervised learning (Isolation Forest)
- **Explainable**: Provides anomaly scores and clear risk levels
- **Realistic**: Designed as a final-year engineering project
- **Modular**: Standalone project that can later integrate with Node.js backends
- **Production-ready**: Includes feature engineering, training, evaluation, and prediction pipelines

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  UPLOAD TRAFFIC (Users)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │   Mock FastAPI Upload Server     │
         │  (mock_server/mock_upload_api)   │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Upload Simulator                │
         │  - Normal users                  │
         │  - Attack patterns               │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Raw Upload Logs (CSV)           │
         │  data/upload_logs.csv            │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Feature Extractor               │
         │  (src/feature_extractor.py)      │
         │  - uploads_per_time_window       │
         │  - duplicate_file_ratio          │
         │  - average_file_size             │
         │  - upload_failure_rate           │
         │  - ... more features             │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Extracted Features (CSV)        │
         │  data/extracted_features.csv     │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Isolation Forest Training       │
         │  (src/train_isolation_forest)    │
         │  - Feature normalization         │
         │  - Model training                │
         │  - Anomaly score calculation     │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Trained Model + Scaler          │
         │  model/isolation_forest.pkl      │
         │  model/scaler.pkl                │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Model Evaluation                │
         │  (src/evaluate_model.py)         │
         │  - Metrics & Performance         │
         │  - Confusion Matrix              │
         │  - Risk Thresholds               │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Prediction Pipeline             │
         │  (src/predict.py)                │
         │  Returns: Risk Level & Score     │
         └──────────────────┬───────────────┘
                           │
                           ▼
         ┌──────────────────────────────────┐
         │  Integration Ready for           │
         │  Node.js Backend (Future)        │
         └──────────────────────────────────┘
```

---

## Feature Engineering Details

### Features Used

1. **uploads_per_time_window** (5-minute rolling window)
   - Detects upload flooding attacks
   - Normal users: 2-5 uploads per 5 min
   - Attackers: 10+ uploads per 5 min

2. **duplicate_file_ratio**
   - Proportion of duplicate file hashes
   - Normal users: 0-10% duplicates
   - Attackers: 50-100% duplicates (same file uploaded repeatedly)

3. **average_file_size** (in bytes)
   - Detects file size abuse
   - Normal users: 100KB - 5MB average
   - Attackers: 50MB+ (to exhaust bandwidth)

4. **upload_failure_rate**
   - Ratio of failed uploads
   - Normal users: 0-5% failure
   - Attackers: May have high failure rate (misconfigured attacks)

5. **max_file_size**
   - Largest single file uploaded
   - Identifies extreme outliers

6. **time_between_uploads_sec**
   - Average seconds between consecutive uploads
   - Normal users: 10-30 seconds
   - Attackers: 0.5-2 seconds (rapid-fire uploads)

7. **total_uploads**
   - Total number of uploads by user

8. **total_bytes_uploaded**
   - Sum of all file sizes

9. **ip_diversity**
   - Number of unique IP addresses used
   - Normal users: 1 IP
   - Attackers: May use multiple IPs

10. **unique_file_hashes**
    - Count of distinct files uploaded
    - Indicator of variety

---

## Machine Learning Details

### Why Isolation Forest?

**Advantages:**
- **Unsupervised**: Works without labeled attack data
- **Efficient**: O(n log n) complexity, scales well
- **Robust**: Handles high-dimensional data naturally
- **Interpretable**: Produces anomaly scores (0-1)
- **Isolation-based**: Isolates anomalies without computing distances

**How It Works:**
1. Randomly selects features and split values
2. Creates isolation trees (partitions that isolate points)
3. Anomalies are isolated with fewer splits (shorter paths)
4. Normal points require more splits to isolate
5. Anomaly score = average path length across ensemble

### Hyperparameters

- **contamination**: 0.1 (assumes 10% of data might be anomalies)
- **n_estimators**: 100 (100 trees in the ensemble)
- **random_state**: 42 (reproducibility)

### Anomaly Score Interpretation

- **Score range**: 0 to 1+
- **0.0 - 0.65**: Normal behavior (safe)
- **0.65 - 0.85**: Suspicious behavior (monitor)
- **0.85+**: Malicious behavior (alert/block)

### Risk Levels

- **NORMAL**: Score < 0.65 (green)
- **SUSPICIOUS**: 0.65 ≤ Score < 0.85 (yellow)
- **MALICIOUS**: Score ≥ 0.85 (red)

---

## Testing Strategy

### Test 1: Duplicate Upload Attack
**What it simulates**: Same file uploaded 10+ times in short period

**Expected behavior**:
- High `duplicate_file_ratio` (>0.8)
- High `uploads_per_time_window` (>8)
- Low `time_between_uploads_sec` (<2)
- Model should flag as anomalous

**Validation**: Check if attacker_0 is detected as malicious

### Test 2: Upload Flood Attack
**What it simulates**: Many different files uploaded very rapidly

**Expected behavior**:
- High `uploads_per_time_window` (>12)
- Low `time_between_uploads_sec` (<1)
- Normal `duplicate_file_ratio` (different files)
- Model should flag as anomalous

**Validation**: Check if attacker_1 is detected as malicious

### Test 3: Large File Abuse
**What it simulates**: Very large files uploaded to exhaust bandwidth

**Expected behavior**:
- Very high `average_file_size` (>50MB)
- Very high `max_file_size` (>100MB)
- High `total_bytes_uploaded`
- Model should flag as anomalous

**Validation**: Check if attacker_2 is detected as malicious

### Test 4: False Positive Validation
**What it checks**: Normal users are not flagged as attackers

**Expected behavior**:
- Normal users should have score < 0.65
- False positive rate should be <5%

**Validation**: Check that 95%+ of normal users are correctly classified

### Test 5: Gradual Behavior Change
**What it tests**: Sudden behavior change from previously normal user

**How to test**: Modify simulator to have normal users suddenly increase uploads
- Ensures model can detect when "normal" changes

---

## Installation and Running

### 1. Environment Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Mock Server

```bash
# Terminal 1: Start the mock FastAPI server
python mock_server/mock_upload_api.py
# Output: Starting Mock Upload API on http://localhost:8000
```

### 3. Run Simulator

```bash
# Terminal 2: Run the upload simulator
python simulator/upload_simulator.py
# This generates traffic for 5 minutes with normal users and attackers
# Logs are written to data/upload_logs.csv
```

### 4. Extract Features

```bash
# After simulator completes
python src/feature_extractor.py
# Output: Features saved to data/extracted_features.csv
```

### 5. Train Model

```bash
python src/train_isolation_forest.py
# Output: 
# - Model saved to model/isolation_forest.pkl
# - Scaler saved to model/scaler.pkl
# - Predictions saved to data/training_predictions.csv
```

### 6. Evaluate Model

```bash
python src/evaluate_model.py
# Output: Performance metrics, confusion matrix, ROC-AUC
```

### 7. Make Predictions

```bash
python src/predict.py
# Output: Risk levels for all users
```

### 8. Exploratory Analysis (Jupyter)

```bash
jupyter notebook notebooks/exploratory_analysis.ipynb
# Open and run all cells for visualizations
```

---

## Complete End-to-End Workflow

```bash
# All-in-one script (run in order)

# Terminal 1
python mock_server/mock_upload_api.py

# Terminal 2 (wait for server to start)
python simulator/upload_simulator.py

# Terminal 3 (after simulator finishes, ~5 min)
python src/feature_extractor.py
python src/train_isolation_forest.py
python src/evaluate_model.py
python src/predict.py

# View results
jupyter notebook notebooks/exploratory_analysis.ipynb
```

---

## Output Files Explained

| File | Purpose |
|------|---------|
| `data/upload_logs.csv` | Raw upload events from simulator |
| `data/extracted_features.csv` | ML features extracted from logs |
| `data/training_predictions.csv` | Model predictions and anomaly scores |
| `model/isolation_forest.pkl` | Trained Isolation Forest model |
| `model/scaler.pkl` | Feature normalization scaler |
| `notebooks/exploratory_analysis.ipynb` | Jupyter notebook with visualizations |

---

## Integration with Node.js Backend

### Integration Points

1. **Batch Prediction (Daily/Hourly)**
   ```javascript
   // Node.js: Call Python script to get batch predictions
   const predictions = await runPythonScript('src/predict.py');
   // Log malicious users to database
   ```

2. **Real-time Prediction (Per Upload)**
   ```javascript
   // Extract features from single upload event
   const userFeatures = extractFeaturesFromUpload(uploadEvent);
   
   // Call Python prediction API
   const result = await predictRisk(userFeatures);
   
   // Block/allow upload based on risk level
   if (result.risk_level === 'MALICIOUS') {
     blockUpload();
   }
   ```

3. **Model Retraining (Weekly)**
   ```javascript
   // Run full pipeline weekly
   - Collect upload logs from production
   - Run feature extraction
   - Retrain Isolation Forest
   - Update model/scaler files
   ```

### API for Integration

**Python predict.py can be wrapped as:**

```javascript
// prediction-api.js
const { spawn } = require('child_process');

async function predictUserRisk(userFeatures) {
  return new Promise((resolve, reject) => {
    const python = spawn('python', ['src/predict.py']);
    
    python.stdin.write(JSON.stringify(userFeatures));
    python.stdin.end();
    
    let output = '';
    python.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    python.on('close', (code) => {
      resolve(JSON.parse(output));
    });
  });
}
```

---

## Expected Results

### Normal Users
- Anomaly scores: 0.0 - 0.4
- 20 normal users with typical behavior
- Should all be classified as NORMAL

### Attack Users
- **Duplicate attacker**: Score 0.8-0.95 (MALICIOUS)
- **Flood attacker**: Score 0.85-0.98 (MALICIOUS)
- **Large file attacker**: Score 0.8-0.92 (MALICIOUS)
- All 3 attackers should be detected

### Performance Metrics (Expected)
- Attack detection rate: 90-100%
- False positive rate: <5%
- ROC-AUC: 0.85-0.95

---

## Troubleshooting

### "Connection refused" error
- Ensure mock server is running on localhost:8000
- Check if port 8000 is in use: `lsof -i :8000` (macOS/Linux)

### "Features file not found"
- Run simulator and feature extractor before training

### "Model file not found"
- Train the model with `train_isolation_forest.py` first

### "No module named 'sklearn'"
- Reinstall requirements: `pip install -r requirements.txt`

---

## Project Structure Summary

```
cloud-drive-ml-security/
├── mock_server/
│   └── mock_upload_api.py          # FastAPI mock upload service
├── simulator/
│   └── upload_simulator.py          # Generate realistic + attack traffic
├── data/
│   ├── upload_logs.csv             # Raw logs (generated)
│   ├── extracted_features.csv      # ML features (generated)
│   └── training_predictions.csv    # Model predictions (generated)
├── src/
│   ├── feature_extractor.py        # Extract features from logs
│   ├── train_isolation_forest.py   # Train the ML model
│   ├── evaluate_model.py           # Evaluate performance
│   └── predict.py                  # Make predictions on new data
├── model/
│   ├── isolation_forest.pkl        # Trained model (generated)
│   └── scaler.pkl                  # Feature scaler (generated)
├── notebooks/
│   └── exploratory_analysis.ipynb  # Jupyter EDA notebook
├── requirements.txt                # Python dependencies
├── README.md                       # This file
└── .gitignore                     # Git ignore rules
```

---

## Key Research Insights

1. **Isolation Forest is ideal for this use case** because:
   - No labeled data needed
   - Naturally detects multiple types of anomalies simultaneously
   - Produces interpretable anomaly scores
   - Computationally efficient

2. **Feature engineering is critical** because:
   - Raw logs are high-dimensional and noisy
   - Well-designed features make anomalies obvious
   - Helps model generalize to new attack patterns

3. **Multiple attack types are detectable** because:
   - Different attacks have different feature signatures
   - Single model can catch duplicate, flood, and size-based attacks
   - Ensemble approach (100 trees) improves robustness

4. **Thresholds should be tuned** based on:
   - Organization's tolerance for false positives
   - Cost of missing attacks vs. blocking legitimate users
   - Can be easily adjusted in `predict.py`

---

## Future Enhancements

1. **Temporal Analysis**: Detect behavior changes over time
2. **Clustering**: Group similar anomalies to identify new attack patterns
3. **Active Learning**: Ask human reviewers to label borderline cases
4. **Real-time Integration**: Stream predictions directly to Node.js backend
5. **Multi-model Ensemble**: Combine Isolation Forest with other algorithms
6. **Deep Learning**: Use autoencoders for more complex pattern detection

---

## Author Notes

This project is suitable for:
- Final-year engineering capstone projects
- Research papers on anomaly detection
- Production deployment with proper monitoring
- Educational purposes to learn ML workflows

All code follows best practices:
- Clean, readable Python
- Comprehensive documentation
- Modular design (easy to extend)
- Proper error handling
- Realistic feature engineering

---

## License

Open source - feel free to use and modify for academic/commercial purposes.
