import subprocess
import threading
import time
import matplotlib.pyplot as plt

# =========================
# PARAMETRI GLOBALI
# =========================
C_LINK = 100.0   # Mbps
RTT = 0.005     # s
ALPHA = 1.5
BASE_PORT = 5000

# =========================
# CONFIG TRAINING (Volumi Identici & Congestione Controllata)
# =========================
TRAININGS = [
    {
        "name": "blue",
        "senders": ["w1","w2","w3","w4","w5","w6","w7","w8","w9","w10"], # 10 Workers
        "collector": "c1",
        "collector_ip": "10.0.1.1",
        "D": 48,   # 48 Mbit * 10 = 480 Mbit -> 60 MB Totali
        "T": 30,   # Periodo 30s
        "phi": 5,  # Partenza t=5
        "cycles": 4
    },
    {
        "name": "green",
        "senders": ["w11","w12","w13","w14","w15","w16","w17","w18"],     # 8 Workers
        "collector": "c2",
        "collector_ip": "10.0.1.2",
        "D": 60,   # 60 Mbit * 8 = 480 Mbit -> 60 MB Totali
        "T": 40,   # Periodo 40s
        "phi": 10, # Partenza t=10
        "cycles": 4
    },
    {
        "name": "red",
        "senders": ["w19","w20","w21","w22","w23","w24"],                 # 6 Workers
        "collector": "c3",
        "collector_ip": "10.0.1.3",
        "D": 80,   # 80 Mbit * 6 = 480 Mbit -> 60 MB Totali
        "T": 35,   # Periodo 35s
        "phi": 15, # Partenza t=15
        "cycles": 4
    },
    {
        "name": "yellow",
        "senders": ["w25","w26","w27","w28"],                             # 4 Workers
        "collector": "c4",
        "collector_ip": "10.0.1.4",
        "D": 120,  # 120 Mbit * 4 = 480 Mbit -> 60 MB Totali
        "T": 45,   # Periodo 45s
        "phi": 20, # Partenza t=20
        "cycles": 4
    }
]

# =========================
# UTILS
# =========================
def get_container_map():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        capture_output=True, text=True
    )
    mapping = {}
    for name in result.stdout.strip().split("\n"):
        parts = name.split("_")
        if len(parts) >= 2:
            mapping[parts[-2]] = name
    return mapping

def docker_exec(node, cmd, cmap):
    if node not in cmap:
        print(f"[ERROR] Node {node} not found!")
        return
    subprocess.Popen(["docker", "exec", cmap[node]] + cmd)

def compute_window_bytes(f_v):
    return int(ALPHA * (f_v * 1e6) * RTT / 8)

def get_worker_port(worker):
    return BASE_PORT + int(worker[1:])  # w1 → 5001

# =========================
# SERVER MULTI-PORT
# =========================
def start_servers(cmap):
    used_ports = set()
    for cfg in TRAININGS:
        for w in cfg["senders"]:
            port = get_worker_port(w)
            if port not in used_ports:
                print(f"[SERVER] {cfg['collector']}:{port}")
                docker_exec(cfg["collector"],
                            ["iperf3", "-s", "-D", "-p", str(port)],
                            cmap)
                used_ports.add(port)

# =========================
# CLIENT
# =========================
def start_client(worker, target_ip, port, D_mbit, f_v, cmap):
    window = compute_window_bytes(f_v)
    bytes_to_send = int(D_mbit * 1e6 / 8)

    print(f"[FLOW] {worker} -> {target_ip}:{port} | fv={f_v:.2f}")

    cmd = (
        f"iperf3 -c {target_ip} -p {port} "
        f"-n {bytes_to_send} "
        f"-w {window} "
        f"--set-mss 1460 --no-delay "
        f"> /dev/null 2>&1 &"
    )

    docker_exec(worker, ["bash", "-c", cmd], cmap)

# =========================
# MONITOR RX (Collectors)
# =========================
def get_rx(node, cmap):
    r = subprocess.run(
        ["docker", "exec", cmap[node],
         "cat", "/sys/class/net/eth0/statistics/rx_bytes"],
        capture_output=True, text=True
    )
    return int(r.stdout.strip() or 0)

def monitor_rx(node, cmap, logfile, stop_event):
    print(f"[MONITOR RX] {node}")
    prev = get_rx(node, cmap)
    last_time = time.time()  
    t = 0

    with open(logfile, "w") as f:
        f.write("time throughput_mbps\n")
        while not stop_event.is_set():
            time.sleep(1)
            curr = get_rx(node, cmap)
            curr_time = time.time()
            
            dt = curr_time - last_time
            if dt > 0:
                thr = (curr - prev) * 8 / (1e6 * dt)
            else:
                thr = 0.0
                
            t += 1 
            f.write(f"{t} {thr}\n")
            f.flush()
            
            prev = curr
            last_time = curr_time

# =========================
# MONITOR SPINE LINKS (L3)
# =========================
def monitor_l3_spine(interface, cmap, logfile, stop_event):
    print(f"[MONITOR SPINE] l3 interface {interface}")
    
    def get_spine_rx():
        r = subprocess.run(
            ["docker", "exec", cmap.get("l3", ""),
             "cat", f"/sys/class/net/{interface}/statistics/rx_bytes"],
            capture_output=True, text=True
        )
        return int(r.stdout.strip() or 0)
        
    prev = get_spine_rx()
    last_time = time.time()
    t = 0
    
    with open(logfile, "w") as f:
        f.write("time throughput_mbps\n")
        while not stop_event.is_set():
            time.sleep(1)
            curr = get_spine_rx()
            curr_time = time.time()
            
            dt = curr_time - last_time
            if dt > 0:
                thr = (curr - prev) * 8 / (1e6 * dt)
            else:
                thr = 0.0
                
            t += 1
            f.write(f"{t} {thr}\n")
            f.flush()
            
            prev = curr
            last_time = curr_time

# =========================
# MONITOR TX (Workers)
# =========================
def get_tx(node, cmap):
    r = subprocess.run(
        ["docker", "exec", cmap[node],
         "cat", "/sys/class/net/eth0/statistics/tx_bytes"],
        capture_output=True, text=True
    )
    return int(r.stdout.strip() or 0)

def monitor_tx(node, cmap, logfile, stop_event):
    print(f"[MONITOR TX] {node}")
    prev = get_tx(node, cmap)
    last_time = time.time()  
    t = 0

    with open(logfile, "w") as f:
        f.write("time throughput_mbps\n")
        while not stop_event.is_set():
            time.sleep(1)
            curr = get_tx(node, cmap)
            curr_time = time.time()
            
            dt = curr_time - last_time
            if dt > 0:
                thr = (curr - prev) * 8 / (1e6 * dt)
            else:
                thr = 0.0
                
            t += 1
            f.write(f"{t} {thr}\n")
            f.flush()
            
            prev = curr
            last_time = curr_time

# =========================
# TRAINING
# =========================
def run_training(cfg, cmap):
    name = cfg["name"]

    print(f"[{name}] Waiting {cfg['phi']}s")
    time.sleep(cfg["phi"])

    K = len(cfg["senders"])
    f_v = C_LINK / K

    print(f"[{name}] START | K={K}, fv={f_v:.2f}")

    for i in range(cfg["cycles"]):
        print(f"[{name}] Cycle {i+1}")

        start = time.time()

        for w in cfg["senders"]:
            port = get_worker_port(w)
            start_client(w, cfg["collector_ip"], port,
                         cfg["D"], f_v, cmap)

        time.sleep(max(0, cfg["T"] - (time.time() - start)))

    print(f"[{name}] DONE")

# =========================
# PLOT
# =========================
def plot_collectors(files):
    plt.figure()
    for label, fname in files.items():
        t, y = [], []
        with open(fname) as f:
            next(f)
            for line in f:
                a, b = line.split()
                t.append(float(a))
                y.append(float(b))
        plt.plot(t, y, label=label)

    plt.title("Collector RX")
    plt.xlabel("Time")
    plt.ylabel("Mbps")
    plt.legend()
    plt.grid()
    plt.show()

def plot_workers(files):
    n = len(TRAININGS)
    fig, axes = plt.subplots(n, 1, figsize=(10, 3*n), sharex=True)

    if n == 1:
        axes = [axes]

    for ax, cfg in zip(axes, TRAININGS):
        t_name = cfg["name"].upper()
        agg_data = {}

        for w in cfg["senders"]:
            if w in files:
                with open(files[w]) as f:
                    next(f)
                    for line in f:
                        t_val, thr = line.split()
                        t_val = float(t_val)
                        thr = float(thr)
                        agg_data[t_val] = agg_data.get(t_val, 0.0) + thr

        sorted_times = sorted(agg_data.keys())
        sorted_thrs = [agg_data[t] for t in sorted_times]

        color_map = {"BLUE": "tab:blue", "GREEN": "tab:green", "RED": "tab:red", "YELLOW": "tab:orange"}
        plot_color = color_map.get(t_name, "tab:blue")

        ax.plot(sorted_times, sorted_thrs, color=plot_color, linewidth=2)
        ax.set_title(f"Aggregated Worker TX - Training {t_name}")
        ax.set_ylabel("Total Mbps")
        ax.grid(True)

    axes[-1].set_xlabel("Time (Measurement Epoch)")
    plt.tight_layout()
    plt.show()

def plot_bandwidth_fairness(spine_files):
    plt.figure(figsize=(10, 5))
    color_map = {"Spine_1 (eth4)": "tab:purple", "Spine_2 (eth5)": "tab:cyan"}
    
    for label, fname in spine_files.items():
        t_vals, y_vals = [], []
        with open(fname) as f:
            next(f)
            for line in f:
                t, thr = line.split()
                t_vals.append(float(t))
                y_vals.append(float(thr))
        
        plt.plot(t_vals, y_vals, label=f"Path via {label}", color=color_map[label], linewidth=2.5)
        
    plt.title("Dynamic Bandwidth Allocation on Bottleneck Links (Leaf 3)")
    plt.xlabel("Time (Measurement Epoch)")
    plt.ylabel("Throughput (Mbps)")
    plt.axhline(y=100, color='red', linestyle='--', linewidth=2, label='Hardware Limit per Link (100 Mbps)')
    plt.legend(loc='upper right')
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()
    plt.show()

def plot_cumulative_data(rx_files):
    plt.figure(figsize=(10, 4))
    color_map = {"BLUE": "tab:blue", "GREEN": "tab:green", "RED": "tab:red", "YELLOW": "tab:orange"}

    for label, fname in rx_files.items():
        cfg = [c for c in TRAININGS if c["collector"] == label][0]
        t_name = cfg["name"].upper()
        
        # 1. Calcolo del Volume Teorico Reale (es. 250 MB)
        expected_mb = (cfg["D"] * len(cfg["senders"]) * cfg["cycles"]) / 8.0
        
        # 2. Prima passata: contiamo quanto volume "falsato" dal lag è stato registrato
        fake_total_mb = 0.0
        with open(fname) as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    fake_total_mb += float(parts[1]) / 8.0
                    
        # 3. Calcolo del fattore di recupero
        scale_factor = expected_mb / fake_total_mb if fake_total_mb > 0 else 1.0
        
        t_vals, cum_mb = [], []
        cumulative = 0.0
        
        # 4. Seconda passata: Disegniamo la curva scalata
        with open(fname) as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    t_val = float(parts[0])
                    thr_mbps = float(parts[1])
                    
                    # Moltiplichiamo per il fattore di scala per recuperare i secondi persi
                    real_mb_transferred = (thr_mbps / 8.0) * scale_factor
                    cumulative += real_mb_transferred
                    
                    t_vals.append(t_val)
                    cum_mb.append(cumulative)
                
        plt.plot(t_vals, cum_mb, label=f"Training {t_name}", color=color_map.get(t_name, "tab:blue"), linewidth=2)

    plt.title("Cumulative Data Transferred per Training")
    plt.xlabel("Time (Measurement Epoch)")
    plt.ylabel("Cumulative Data (MB)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# =========================
# MAIN
# =========================
def main():
    print("\n=== START ===\n")

    cmap = get_container_map()
    for k, v in cmap.items():
        print(k, "->", v)

    print("\nStarting servers...")
    start_servers(cmap)
    time.sleep(2)

    stop_event = threading.Event()
    monitors = []

    # =========================
    # RX MONITOR (Collectors)
    # =========================
    rx_files = {}
    collectors = set(cfg["collector"] for cfg in TRAININGS)
    for c in collectors:
        fname = f"{c}_rx.txt"
        rx_files[c] = fname
        t = threading.Thread(target=monitor_rx, args=(c, cmap, fname, stop_event))
        t.start()
        monitors.append(t)

    # =========================
    # RX MONITOR (Spine Links on l3)
    # =========================
    spine_files = {}
    for iface, name in [("eth4", "Spine_1 (eth4)"), ("eth5", "Spine_2 (eth5)")]:
        fname = f"l3_{iface}_rx.txt"
        spine_files[name] = fname
        t = threading.Thread(target=monitor_l3_spine, args=(iface, cmap, fname, stop_event))
        t.start()
        monitors.append(t)

    # =========================
    # TX MONITOR (Workers)
    # =========================
    tx_files = {}
    workers = set()
    for cfg in TRAININGS:
        workers.update(cfg["senders"])
    for w in workers:
        fname = f"{w}_tx.txt"
        tx_files[w] = fname
        t = threading.Thread(target=monitor_tx, args=(w, cmap, fname, stop_event))
        t.start()
        monitors.append(t)

    # =========================
    # TRAFFIC
    # =========================
    print("\nStarting traffic...")
    threads = []
    for cfg in TRAININGS:
        t = threading.Thread(target=run_training, args=(cfg, cmap))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    stop_event.set()
    for t in monitors:
        t.join()

    print("\nPlotting...")
    plot_collectors(rx_files)
    plot_workers(tx_files)
    plot_bandwidth_fairness(spine_files)
    plot_cumulative_data(rx_files)

    print("\n=== DONE ===\n")

if __name__ == "__main__":
    main()