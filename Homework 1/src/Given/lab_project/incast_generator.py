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
# CONFIG TRAINING
# =========================
TRAININGS = [
    {
        "name": "blue",
        "senders": ["w1","w2","w3","w4","w5","w6","w7","w8","w9","w10"],
        "collector": "c1",
        "collector_ip": "10.0.1.1",
        "D": 50,
        "T": 30,
        "phi": 1,
        "cycles": 4
    },
    {
        "name": "green",
        "senders": ["w11","w12","w13","w14","w15","w16","w17","w18"],
        "collector": "c2",
        "collector_ip": "10.0.1.2",
        "D": 62.5,
        "T": 40,
        "phi": 2.5,
        "cycles": 4
    },
    {
        "name": "red",
        "senders": ["w19","w20","w21","w22","w23","w24"],
        "collector": "c3",
        "collector_ip": "10.0.1.3",
        "D": 83.35,
        "T": 30,
        "phi": 4,
        "cycles": 4
    },
    {
        "name": "yellow",
        "senders": ["w25","w26","w27","w28"],
        "collector": "c4",
        "collector_ip": "10.0.1.4",
        "D": 125,
        "T": 40,
        "phi": 5,
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
# MONITOR RX
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
    t = 0

    with open(logfile, "w") as f:
        f.write("time throughput_mbps\n")

        while not stop_event.is_set():
            time.sleep(1)
            curr = get_rx(node, cmap)
            thr = (curr - prev) * 8 / 1e6
            f.write(f"{t} {thr}\n")
            f.flush()
            prev = curr
            t += 1


# =========================
# MONITOR TX
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
    t = 0

    with open(logfile, "w") as f:
        f.write("time throughput_mbps\n")

        while not stop_event.is_set():
            time.sleep(1)
            curr = get_tx(node, cmap)
            thr = (curr - prev) * 8 / 1e6
            f.write(f"{t} {thr}\n")
            f.flush()
            prev = curr
            t += 1


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
    
    # Purpose: It aggregates the TX throughput of all workers belonging to the same training
    
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

    axes[-1].set_xlabel("Time (s)")
    plt.tight_layout()
    plt.show()

def plot_bandwidth_fairness(rx_files):
    
    # Purpose: Stacked area chart showing how the SDN controller dynamically 
    
    plt.figure(figsize=(10, 5))
    
    all_times = set()
    data_series = {label: {} for label in rx_files.keys()}
    
    for label, fname in rx_files.items():
        with open(fname) as f:
            next(f)
            for line in f:
                t_val, thr = line.split()
                t_val = float(t_val)
                all_times.add(t_val)
                data_series[label][t_val] = float(thr)
                
    sorted_times = sorted(list(all_times))
    
    y_data = []
    labels = []
    colors = []
    color_map = {"c1": "tab:blue", "c2": "tab:green", "c3": "tab:red", "c4": "tab:orange"}
    name_map = {"c1": "BLUE", "c2": "GREEN", "c3": "RED", "c4": "YELLOW"}
    
    for c in ["c1", "c2", "c3", "c4"]:
        y = [data_series[c].get(t, 0.0) for t in sorted_times]
        y_data.append(y)
        labels.append(f"Training {name_map[c]}")
        colors.append(color_map[c])
        
    plt.stackplot(sorted_times, y_data, labels=labels, colors=colors, alpha=0.85)
    
    plt.title("Dynamic Bandwidth Allocation (Capacity-Aware Fairness)")
    plt.xlabel("Time (s)")
    plt.ylabel("Aggregated Throughput (Mbps)")
    
    plt.axhline(y=100, color='black', linestyle='--', linewidth=2, label='Single Link Hardware Limit (100 Mbps)')
    
    plt.legend(loc='upper right')
    plt.grid(True, linestyle=':', alpha=0.6)
    plt.tight_layout()
    plt.show()

def plot_cumulative_data(rx_files):
    
    # Purpose: It visualizes the completion of ML cycles as cumulative data ( MB )
    
    plt.figure(figsize=(10, 4))
    color_map = {"BLUE": "tab:blue", "GREEN": "tab:green", "RED": "tab:red", "YELLOW": "tab:orange"}

    for label, fname in rx_files.items():
        t_name = [cfg["name"].upper() for cfg in TRAININGS if cfg["collector"] == label][0]
        t_vals, cum_mb = [], []
        cumulative = 0.0
        
        with open(fname) as f:
            next(f)
            for line in f:
                t_val, thr_mbps = line.split()
                # 1 Mbps = 0.125 MB/s. Multiplying by 1 second polling interval
                mb_transferred = float(thr_mbps) / 8.0 
                cumulative += mb_transferred
                t_vals.append(float(t_val))
                cum_mb.append(cumulative)
                
        plt.plot(t_vals, cum_mb, label=f"Training {t_name}", color=color_map.get(t_name, "tab:blue"), linewidth=2)

    plt.title("Cumulative Data Transferred per Training")
    plt.xlabel("Time (s)")
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
    # RX MONITOR (collector)
    # =========================
    rx_files = {}
    collectors = set(cfg["collector"] for cfg in TRAININGS)

    for c in collectors:
        fname = f"{c}_rx.txt"
        rx_files[c] = fname

        t = threading.Thread(target=monitor_rx,
                             args=(c, cmap, fname, stop_event))
        t.start()
        monitors.append(t)

    # =========================
    # TX MONITOR (workers)
    # =========================
    tx_files = {}
    workers = set()
    for cfg in TRAININGS:
        workers.update(cfg["senders"])

    for w in workers:
        fname = f"{w}_tx.txt"
        tx_files[w] = fname

        t = threading.Thread(target=monitor_tx,
                             args=(w, cmap, fname, stop_event))
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
    
    # Note: Following instructions are related to the calls for new plots
    plot_bandwidth_fairness(rx_files)
    plot_cumulative_data(rx_files)

    print("\n=== DONE ===\n")

if __name__ == "__main__":
    main()