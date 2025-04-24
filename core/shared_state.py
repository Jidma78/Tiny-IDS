# core/shared_state.py

from collections import defaultdict

# Historique des connexions par IP et port
log_dic = defaultdict(lambda: {
    "port_dst": defaultdict(int)
})

# Bruteforce déjà détectés (clé: (ip, port), valeur: timestamp)
bruteforce_ips = {}

# Pour limiter les logs flood (clé: (ip, port), valeur: timestamp dernière alerte)
last_alert_time = {}

# Verbosité globale (si True, on print tous les logs)
verbose = False
