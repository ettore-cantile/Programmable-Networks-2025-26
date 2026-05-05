import time
import subprocess
import sys
from datetime import datetime

# Flexible argument checking
if len(sys.argv) < 3:
    print("Usage: python3 worker_app.py <COLLECTOR_IP> <PORT> [BURST_DURATION_SEC] [ROUND_PERIOD_SEC]")
    print("Base Example: python3 worker_app.py 10.0.0.101 8000")
    print("Custom Example: python3 worker_app.py 10.0.0.102 8000 5 20")
    sys.exit(1)

TARGET_IP = sys.argv[1]
TARGET_PORT = sys.argv[2]

# If provided by the user, use custom values, otherwise use defaults (3s burst, 15s round)
BURST_DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 3
ROUND_PERIOD = int(sys.argv[4]) if len(sys.argv) > 4 else 15 # If provided by the user, use custom values, otherwise use defaults (3s burst, 15s round)

print(f"[*] Initializing ML Worker towards {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Training Parameters: Payload Burst = {BURST_DURATION}s | Round = {ROUND_PERIOD}s")
print("[*] Waiting for global synchronization signal...")

# Mathematical synchronization: wait for an exact multiple of the period
while int(time.time()) % ROUND_PERIOD != 0:
    time.sleep(0.01)

sync_time = datetime.now().strftime('%H:%M:%S.%f')[:-3]
print(f"[!] Synchronization reached at {sync_time}! Starting training.")

round_num = 1
while True:
    round_start = datetime.now().strftime('%H:%M:%S')
    print(f"\n--- Round {round_num} | Start: {round_start} ---")
    print(f"-> Sending model weights (Burst of {BURST_DURATION}s)...")
    
    # Executes iperf3 and redirects output to "nowhere" to keep the terminal clean
    subprocess.run(
        ["iperf3", "-c", TARGET_IP, "-p", TARGET_PORT, "-t", str(BURST_DURATION)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    print("-> Transmission completed. Local computation phase (Waiting)...")
    
    # Calculates wait time using absolute clock to avoid drift
    next_round_time = (int(time.time()) // ROUND_PERIOD + 1) * ROUND_PERIOD
    sleep_time = next_round_time - time.time()
    
    if sleep_time > 0:
        time.sleep(sleep_time)
        
    round_num += 1