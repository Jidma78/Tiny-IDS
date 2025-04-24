from core.sniffer import sniff_packets

if __name__ == "__main__":
    try:
        sniff_packets()
    except KeyboardInterrupt:
        print("\n[*] Sniffing interrompu.")
