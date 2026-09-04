
from parsers.linux import parse_linux
import sys

if len(sys.argv) != 2:
    print("usage: python3 analyzer.py pathoffile ~/auth-file.log")
    sys.exit(1)

log_file = sys.argv[1]

failed_logins = {}
suspicious_ips = {}
http_errors = {}
sudo_commands = {}
db_failures = {}

# Alert counters
ssh_alerts = 0
db_alerts = 0
http_alerts = 0
sudo_alerts = 0
suspicious_ip_alerts = 0

sensitive_commands = [
    "systemctl",
    "journalctl",
    "ss",
]

try:
    with open(log_file, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            result = parse_linux(line)

            if result["event_type"] == "DB_LOGIN_FAILURE":
                source_ip = result["source_ip"]

                if source_ip:
                    if source_ip in db_failures:
                        db_failures[source_ip]["count"] += 1
                        db_failures[source_ip]["event"] = result
                    else:
                        db_failures[source_ip] = {
                            "count": 1,
                            "event": result
                        }

            if result["status_code"] == 401 or result["status_code"] == 403:
                source_ip = result["source_ip"]

                if source_ip:
                    if source_ip in http_errors:
                        http_errors[source_ip] += 1
                    else:
                        http_errors[source_ip] = 1

            source_ip = result["source_ip"]

            if source_ip:
                if source_ip in suspicious_ips:
                    suspicious_ips[source_ip] += 1
                else:
                    suspicious_ips[source_ip] = 1

            if result["event_type"] == "LOGIN_FAILURE":

                if source_ip in failed_logins:
                    failed_logins[source_ip]["count"] += 1
                    failed_logins[source_ip]["event"] = result
                else:
                    failed_logins[source_ip] = {
                        "count": 1,
                        "event": result
                    }

            if result["event_type"] == "SUDO_COMMAND":
                command = result["command"]

                if command:
                    for sensitive in sensitive_commands:
                        if sensitive in command:
                            sudo_alerts += 1
                            print("[ALERT] Sensitive sudo command detected")
                            print(f"User: {result['username']}")
                            print(f"Command: {command}")

    # SSH brute-force alerts
    for ip, data in failed_logins.items():
        if data["count"] >= 5:
            ssh_alerts += 1

            event = data["event"]

            print("[ALERT] Possible brute-force activity")
            print(f"Timestamp: {event['timestamp']}")
            print(f"Host: {event['hostname']}")
            print(f"Service: {event['service']}")
            print(f"User: {event['username']}")
            print(f"Source IP: {ip}")
            print(f"Failed attempts: {data['count']}")

    # Suspicious IP alerts
    for ip, count in suspicious_ips.items():
        if count >= 5:
            suspicious_ip_alerts += 1

            print("[ALERT] Suspicious IP activity")
            print(f"Source IP: {ip}")
            print(f"Total events: {count}")

    # HTTP anomaly alerts
    for ip, count in http_errors.items():
        if count >= 3:
            http_alerts += 1

            print("[ALERT] HTTP anomaly detected")
            print(f"Source IP: {ip}")
            print(f"HTTP errors: {count}")

    # Database brute-force alerts
    for ip, data in db_failures.items():
        if data["count"] >= 5:
            db_alerts += 1

            event = data["event"]

            print("[ALERT] Possible database brute-force activity")
            print(f"Timestamp: {event['timestamp']}")
            print(f"Host: {event['hostname']}")
            print(f"Service: {event['service']}")
            print(f"User: {event['username']}")
            print(f"Source IP: {ip}")
            print(f"Failed attempts: {data['count']}")

    # SOC Investigation Summary
    print()
    print("========== SOC INVESTIGATION SUMMARY ==========")
    print()
    print(f"SSH brute-force alerts:       {ssh_alerts}")
    print(f"Database brute-force alerts:  {db_alerts}")
    print(f"HTTP anomaly alerts:          {http_alerts}")
    print(f"Sensitive sudo alerts:        {sudo_alerts}")
    print(f"Suspicious IP alerts:         {suspicious_ip_alerts}")
    print()
    print("===============================================")

except FileNotFoundError:
    print(f"File {log_file} not Found")
    sys.exit(1)