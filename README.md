# 🛡️ Tiny-IDS

A lightweight Intrusion Detection System in Python that watches live
traffic, flags **SYN-scans** and **single-port brute-force attacks**, and
logs concise, human-readable alerts.

---

## 🧩 Features

| Module          | Default trigger (sliding window)                         | Alert life-cycle                          |
|-----------------|----------------------------------------------------------|-------------------------------------------|
| **SYN-scan**    | Same **source IP** touches **> 30 distinct ports** on us within **60 s** | 1️⃣ *BEGIN* alert<br>2️⃣ Update every **10 s** while threshold is still exceeded<br>3️⃣ *END* summary with total ports & duration |
| **Brute-force** | Same **source IP** opens **> 200 connections** to **one port** within **60 s** | Same 3-step cycle (begin / Δ 10 s / end) |

* **Outgoing packets ignored** – only inbound traffic is analysed.  
* Pick **one local interface/IP** or **all** at start-up.  
* Alerts written to `output/log/id.log` (plain text, rotates easily).

---

## 🧰 Requirements

| Package     | Version |
|-------------|---------|
| Python      | **3.9 +** |
| scapy       | ≥ 2.5 |
| netifaces   | ≥ 0.11 |

```bash
python -m pip install -r requirements.txt


## 🚀 Quick start

```bash
git clone https://github.com/<your-user>/tiny-ids.git
cd tiny-ids
python main.py          # choose interface when prompted
```


1. Run nmap or Hydra against the sensor to test.
2. Watch alerts in the console or open output/log/id.log.


## ⚙️ Configuration (config.py)

Variable | Description | Default
PORT_SCAN_THRESHOLD | Ports > N → raise SYN-scan | 30
BRUTEFORCE_THRESHOLD | Conns > N on one port → raise brute-force | 200
TIME_WINDOW | Sliding-window length (seconds) | 60
ALERT_INTERVAL | Seconds between live updates during an incident | 10
MY_LOCAL_IP | Fixed IP to protect (or None to pick at start) | None


Adjust these values to fit your network noise or attack simulation needs.
All logic is in detection/syn_scan.py and detection/bruteforce.py –
feel free to tweak thresholds, add new detectors, or hook into your SIEM/webhook.

## 🗂️ Project layout

```bash
tiny-ids/
│
├─ core/           # low-level sniffer & logger
├─ detection/      # syn_scan.py, bruteforce.py
├─ utils/          # interface picker, optional port-scanner
├─ output/log/     # alert log
└─ main.py         # entry point
```
