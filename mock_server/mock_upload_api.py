"""
Mock FastAPI Server for Upload Simulation
Purpose: Simulate a cloud file upload API that accepts file uploads and logs them
This is used to generate realistic upload traffic for training the ML model
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import os
import hashlib
from datetime import datetime
import csv
import time

app = FastAPI(title="Mock CloudDrive Upload API")

# Configuration
UPLOAD_LOG_FILE = "data/upload_logs.csv"
UPLOAD_STORAGE_DIR = "data/uploads"

# Ensure directories exist
os.makedirs(UPLOAD_STORAGE_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

# Initialize CSV log file if it doesn't exist
if not os.path.exists(UPLOAD_LOG_FILE):
    with open(UPLOAD_LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'timestamp', 'user_id', 'ip_address', 'file_hash', 'file_size',
            'filename', 'upload_duration_ms', 'success', 'error_code'
        ])


def calculate_file_hash(content: bytes) -> str:
    """Calculate SHA256 hash of file content"""
    return hashlib.sha256(content).hexdigest()


@app.post("/upload")
async def upload_file(
    user_id: str,
    ip_address: str,
    file: UploadFile = File(...)
):
    """
    Upload a file to the mock storage
    Args:
        user_id: User identifier
        ip_address: Client IP address
        file: File to upload
    Returns:
        JSON response with file metadata and hash
    """
    try:
        start_time = time.time()
        content = await file.read()
        upload_duration = (time.time() - start_time) * 1000  # Convert to ms

        file_hash = calculate_file_hash(content)
        file_size = len(content)
        timestamp = datetime.utcnow().isoformat()

        # Store file metadata in CSV
        with open(UPLOAD_LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                user_id,
                ip_address,
                file_hash,
                file_size,
                file.filename,
                upload_duration,
                1,  # success
                None  # no error
            ])

        return JSONResponse({
            "status": "success",
            "file_hash": file_hash,
            "file_size": file_size,
            "filename": file.filename,
            "timestamp": timestamp
        })

    except Exception as e:
        timestamp = datetime.utcnow().isoformat()
        # Log failed upload
        with open(UPLOAD_LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                timestamp,
                user_id,
                ip_address,
                None,
                0,
                file.filename if file else "unknown",
                0,
                0,  # failure
                str(type(e).__name__)
            ])
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    print("Starting Mock Upload API on http://localhost:8000")
    print(f"Logs will be saved to {UPLOAD_LOG_FILE}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
