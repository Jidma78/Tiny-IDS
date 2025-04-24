LOG_FILE = "output/log/ids.log"

# IP address of the local machine to protect (None = auto-detect)
MY_LOCAL_IP = None

# Sliding window (in seconds) used to evaluate attack thresholds
TIME_WINDOW = 60

# If a single source IP sends SYNs to more than N unique ports → raise SYN scan
PORT_SCAN_THRESHOLD = 30

# If a single source IP makes more than N connections to a single port → raise brute-force
BRUTEFORCE_THRESHOLD = 200

# Interval between live "still ongoing" updates (in seconds)
ALERT_INTERVAL = 10

# Force summary reminder every N seconds even if no new packets
SUMMARY_INTERVAL = 30