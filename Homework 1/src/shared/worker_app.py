import time
import subprocess
import sys
from datetime import datetime

# Flexible argument checking for execution
if len(sys.argv) < 3:
    print("Usage: python3 worker_app.py <COLLECTOR_IP> <PORT> [PAYLOAD_SIZE_MB] [ROUND_PERIOD_SEC]")
    print("Base Example: python3 worker_app.py 10.0.0.101 8000")
    print("Custom Example: python3 worker_app.py 10.0.0.102 8000 5 20")
    sys.exit(1)

TARGET_IP = sys.argv[1]
TARGET_PORT = sys.argv[2]

# If provided by the user, use custom values, otherwise use defaults
PAYLOAD_SIZE_MB = int(sys.argv[3]) if len(sys.argv) > 3 else 24
ROUND_PERIOD = int(sys.argv[4]) if len(sys.argv) > 4 else 20

print(f"[*] Initializing ML Worker towards {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Training Parameters: Payload Size = {PAYLOAD_SIZE_MB}MB | Round = {ROUND_PERIOD}s")
print("[*] Waiting for global synchronization signal...")

# Mathematical synchronization: wait for an exact multiple of the period to align all workers
while int(time.time()) % ROUND_PERIOD != 0:
    time.sleep(0.01)

sync_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
print(f"[!] Synchronization reached at {sync_time}! Starting training.")

round_num = 1
while True:
    round_start = datetime.now().strftime('%H:%M:%S')
    print(f"\n--- Round {round_num} | Start: {round_start} ---")
    print(f"-> Sending model weights ({PAYLOAD_SIZE_MB}MB) using iperf (v2)...")
    
    # Executes iperf (v2) which supports simultaneous connections for true Incast
    result = subprocess.run(
        ["iperf", "-c", TARGET_IP, "-p", str(TARGET_PORT), "-n", f"{PAYLOAD_SIZE_MB}M"]
    )
    
    # Check if the transmission was successful or if the network dropped it
    if result.returncode != 0:
        print("[!] WARNING: Transmission failed (Incast too severe or network error).")
    else:
        print("-> Transmission completed successfully.")
    
    # Calculates wait time using absolute clock to avoid temporal drift across rounds
    next_round_time = (int(time.time()) // ROUND_PERIOD + 1) * ROUND_PERIOD
    sleep_time = next_round_time - time.time()
    
    if sleep_time > 0:
        print(f"-> Local computation phase. Waiting {sleep_time:.1f}s for next round...")
        time.sleep(sleep_time)
    else:
        print("[!] WARNING: Previous round exceeded the time limit! Overlap occurring.")
        
    round_num += 1