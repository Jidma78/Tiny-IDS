import netifaces, sys

def list_local_ips():
    """Retourne [(iface, ip)] sans doublon, loopback compris."""
    seen = set()
    for iface in netifaces.interfaces():
        for fam, addrs in netifaces.ifaddresses(iface).items():
            if fam == netifaces.AF_INET:
                for a in addrs:
                    ip = a["addr"]
                    if ip not in seen:
                        seen.add(ip)
                        yield iface, ip

def choose_local_ip():
    ips = list(list_local_ips())
    print("╭─ Interfaces détectées ───────────────────────────")
    for idx, (iface, ip) in enumerate(ips, 1):
        print(f"│ {idx:2d}. {iface:<10}  {ip}")
    print("│  0. (toutes)")
    print("╰──────────────────────────────────────────────────")

    try:
        choice = int(input("Sélectionne le numéro d’interface à surveiller : "))
    except (ValueError, EOFError):
        choice = -1

    if choice == 0:
        return None              # toutes les IP
    if 1 <= choice <= len(ips):
        return ips[choice-1][1]  # l’IP choisie
    print("Choix invalide, surveillance de toutes les IP.")
    return None
