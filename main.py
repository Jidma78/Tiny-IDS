# main.py
"""
Entry point: optionally ask the user which local interface/IP to watch,
then start the packet sniffer.
"""
from core.sniffer import sniff_packets
from utils.netinfo import choose_local_ip
import config


def main() -> None:
    if config.MY_LOCAL_IP is None:
        config.MY_LOCAL_IP = choose_local_ip()  # can stay None (listen on all)

    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("\n[*] Sniffing stopped.")


if __name__ == "__main__":
    main()
