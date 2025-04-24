# detection/syn_scan.py
"""
SYN-scan detector.

Raises an alert when a remote IP touches more than
PORT_SCAN_THRESHOLD *unique* destination ports on the local host
within the sliding TIME_WINDOW.

While the threshold is exceeded the detector:
* logs an update every ALERT_INTERVAL seconds;
* prints a single “END” summary once traffic drops below the threshold.
"""
from __future__ import annotations

import time
from scapy.all import IP, TCP

from config import (
    MY_LOCAL_IP,
    TIME_WINDOW,
    PORT_SCAN_THRESHOLD,
    ALERT_INTERVAL,
)
from core.logger import log_alert, log_error
from utils.netinfo import list_local_ips

# ──────────────────────────────────────────────────────────────
LOCAL_IPS: set[str] = {ip for _, ip in list_local_ips()}

# ip_src -> per-incident state
_incidents: dict[str, dict] = {}
# structure:
# {
#     "ports": {port: last_seen_ts},
#     "incident": bool,
#     "ports_total": set[int],
#     "start": float,
#     "last_alert": float,
# }
# ──────────────────────────────────────────────────────────────


def analyze(pkt) -> None:
    """Scapy callback: inspect each TCP packet."""
    try:
        if IP not in pkt or TCP not in pkt:
            return

        ip_src, ip_dst = pkt[IP].src, pkt[IP].dst

        # Ignore outbound traffic or traffic not directed to us
        if ip_src in LOCAL_IPS or ip_dst not in LOCAL_IPS:
            return
        if MY_LOCAL_IP and ip_dst != MY_LOCAL_IP:
            return

        flags = int(pkt[TCP].flags)
        # Keep only “pure” SYN (SYN = 1, ACK = 0)
        if not (flags & 0x02) or (flags & 0x10):
            return

        port_dst = int(pkt[TCP].dport)
        now = time.time()

        rec = _incidents.setdefault(
            ip_src,
            {
                "ports": {},
                "incident": False,
                "ports_total": set(),
                "start": 0.0,
                "last_alert": 0.0,
            },
        )

        # Sliding-window cleanup
        rec["ports"][port_dst] = now
        rec["ports"] = {p: ts for p, ts in rec["ports"].items() if now - ts <= TIME_WINDOW}
        current_port_count = len(rec["ports"])

        # ── Incident starts ─────────────────────────────────────────
        if not rec["incident"] and current_port_count > PORT_SCAN_THRESHOLD:
            rec.update(
                incident=True,
                start=now,
                last_alert=now,
                ports_total=set(rec["ports"]),
            )
            log_alert(
                f"[SYN SCAN] {ip_src} ➜ {ip_dst} : "
                f"{current_port_count} unique ports (begin)"
            )
            return

        # ── Incident ongoing ───────────────────────────────────────
        if rec["incident"]:
            rec["ports_total"].add(port_dst)

            # periodic update
            if now - rec["last_alert"] >= ALERT_INTERVAL:
                log_alert(
                    f"[SYN SCAN] {ip_src} ➜ {ip_dst} : "
                    f"{current_port_count} ports (Δ {ALERT_INTERVAL}s)"
                )
                rec["last_alert"] = now

            # incident ends
            if current_port_count <= PORT_SCAN_THRESHOLD:
                duration = int(now - rec["start"])
                total_ports = len(rec["ports_total"])
                log_alert(
                    f"[SYN SCAN] END {ip_src} ➜ {ip_dst} : "
                    f"{total_ports} unique ports in {duration}s"
                )
                rec.update(incident=False, ports_total=set())

    except Exception as exc:  # pragma: no cover
        log_error(f"[SYN SCAN] exception: {exc}")
