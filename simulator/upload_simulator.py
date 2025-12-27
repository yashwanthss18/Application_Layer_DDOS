"""
Upload Simulator
Purpose: Generate realistic and attack upload traffic patterns
Simulates:
- Normal users with typical upload patterns
- Attackers with malicious patterns (duplicates, floods, large files)
Outputs: CSV log file compatible with feature extraction
"""

import requests
import random
import time
import hashlib
import os
from datetime import datetime, timedelta
from threading import Thread
import csv

# Configuration
MOCK_SERVER_URL = "http://localhost:8000"
LOG_FILE = "data/upload_logs.csv"
NUM_NORMAL_USERS = 20
NUM_ATTACKERS = 3
SIMULATION_DURATION_SECONDS = 300  # 5 minutes


def get_file_hash(content: bytes) -> str:
    """Calculate SHA256 hash"""
    return hashlib.sha256(content).hexdigest()


def generate_test_file(size_kb: int, content: str = "test") -> bytes:
    """Generate dummy file content of specified size"""
    base_content = content.encode()
    multiplier = max(1, (size_kb * 1024) // len(base_content))
    return (base_content * multiplier)[:size_kb * 1024]


class NormalUser:
    """Simulates a normal, legitimate user"""

    def __init__(self, user_id: str, ip_address: str):
        self.user_id = user_id
        self.ip_address = ip_address
        self.upload_count = 0
        self.file_hashes = []

    def simulate(self, duration: int):
        """Normal user: uploads 2-5 files during the period, small to medium size"""
        end_time = time.time() + duration
        num_uploads = random.randint(2, 5)

        while time.time() < end_time and self.upload_count < num_uploads:
            file_size_kb = random.randint(100, 5000)  # 100KB to 5MB
            file_content = generate_test_file(file_size_kb, f"normal_user_{self.user_id}")

            self._upload_file(file_content, f"file_{self.upload_count}.txt")
            self.upload_count += 1
            self.file_hashes.append(get_file_hash(file_content))

            # Normal users wait between uploads
            wait_time = random.uniform(10, 30)
            time.sleep(wait_time)

    def _upload_file(self, content: bytes, filename: str):
        """Upload file to mock server"""
        try:
            files = {'file': (filename, content)}
            params = {
                'user_id': self.user_id,
                'ip_address': self.ip_address
            }
            response = requests.post(
                f"{MOCK_SERVER_URL}/upload",
                files=files,
                params=params,
                timeout=5
            )
            if response.status_code == 200:
                print(f"[{self.user_id}] Uploaded {filename} ({len(content)} bytes)")
            else:
                print(f"[{self.user_id}] Upload failed: {response.status_code}")
        except Exception as e:
            print(f"[{self.user_id}] Upload error: {str(e)}")


class AttackerUser:
    """Simulates an attacker with malicious patterns"""

    def __init__(self, user_id: str, ip_address: str, attack_type: str = "duplicate"):
        self.user_id = user_id
        self.ip_address = ip_address
        self.attack_type = attack_type
        self.upload_count = 0

    def simulate(self, duration: int):
        """Simulate attack pattern"""
        if self.attack_type == "duplicate":
            self._duplicate_attack(duration)
        elif self.attack_type == "flood":
            self._flood_attack(duration)
        elif self.attack_type == "large_file":
            self._large_file_attack(duration)

    def _duplicate_attack(self, duration: int):
        """Upload same file repeatedly (10+ times in duration)"""
        print(f"[{self.user_id}] Starting DUPLICATE attack")
        end_time = time.time() + duration
        file_content = generate_test_file(500, "duplicate_attack")

        while time.time() < end_time:
            self._upload_file(file_content, f"duplicate_{self.upload_count}.txt")
            self.upload_count += 1
            time.sleep(2)  # Minimal wait between uploads

    def _flood_attack(self, duration: int):
        """Upload many different files rapidly (high frequency)"""
        print(f"[{self.user_id}] Starting FLOOD attack")
        end_time = time.time() + duration

        while time.time() < end_time:
            file_size_kb = random.randint(50, 200)
            file_content = generate_test_file(file_size_kb, f"flood_{self.upload_count}")
            self._upload_file(file_content, f"flood_{self.upload_count}.txt")
            self.upload_count += 1
            time.sleep(0.5)  # Very short wait - rapid-fire uploads

    def _large_file_attack(self, duration: int):
        """Upload large files to exhaust bandwidth (3-4 large files)"""
        print(f"[{self.user_id}] Starting LARGE_FILE attack")
        end_time = time.time() + duration
        num_large_files = random.randint(3, 4)

        while time.time() < end_time and self.upload_count < num_large_files:
            file_size_kb = random.randint(50000, 100000)  # 50-100 MB
            file_content = generate_test_file(file_size_kb, f"large_{self.upload_count}")
            self._upload_file(file_content, f"large_file_{self.upload_count}.bin")
            self.upload_count += 1
            time.sleep(5)

    def _upload_file(self, content: bytes, filename: str):
        """Upload file to mock server"""
        try:
            files = {'file': (filename, content)}
            params = {
                'user_id': self.user_id,
                'ip_address': self.ip_address
            }
            response = requests.post(
                f"{MOCK_SERVER_URL}/upload",
                files=files,
                params=params,
                timeout=10
            )
            if response.status_code == 200:
                print(f"[{self.user_id}] {self.attack_type.upper()} - Uploaded {filename} ({len(content)} bytes)")
        except Exception as e:
            print(f"[{self.user_id}] Upload error: {str(e)}")


def run_simulation():
    """Run the complete simulation"""
    print("\n" + "="*60)
    print("CloudDrive ML Security - Upload Simulator")
    print("="*60)
    print(f"Starting simulation for {SIMULATION_DURATION_SECONDS} seconds...")
    print(f"Normal users: {NUM_NORMAL_USERS}")
    print(f"Attackers: {NUM_ATTACKERS}")
    print("="*60 + "\n")

    threads = []

    # Create and start normal users
    for i in range(NUM_NORMAL_USERS):
        user = NormalUser(
            user_id=f"normal_user_{i}",
            ip_address=f"192.168.1.{100 + i}"
        )
        t = Thread(target=user.simulate, args=(SIMULATION_DURATION_SECONDS,), daemon=True)
        threads.append(t)
        t.start()

    # Create and start attackers
    attack_types = ["duplicate", "flood", "large_file"]
    for i in range(NUM_ATTACKERS):
        attacker = AttackerUser(
            user_id=f"attacker_{i}",
            ip_address=f"10.0.0.{i}",
            attack_type=attack_types[i % len(attack_types)]
        )
        t = Thread(target=attacker.simulate, args=(SIMULATION_DURATION_SECONDS,), daemon=True)
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join(timeout=SIMULATION_DURATION_SECONDS + 30)

    print("\n" + "="*60)
    print("Simulation completed!")
    print(f"Logs saved to: {LOG_FILE}")
    print("="*60)


if __name__ == "__main__":
    run_simulation()
