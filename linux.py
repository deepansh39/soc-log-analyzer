import re
def parse_linux(line):
    event = {
    "timestamp": None,
    "hostname": None,
    "service": None,
    "pid": None,
    "username": None,
    "source_ip": None,
    "source_port": None,
    "event_type": None,
    "command": None,
    "database": None,
    "http_method": None,
    "status_code": None,
    "platform": "linux"
    }

    parts = line.split()

    event["timestamp"] = parts[0]
    if "Failed password" in line:
        event["event_type"]="LOGIN_FAILURE"
        match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)",
            line
        )
        if match:
            event["username"] = match.group(1)
            event["source_ip"] = match.group(2)
            event["source_port"] = int(match.group(3))
    elif "event=AUTH_SUCCESS" in line:
        event["event_type"] = "LOGIN_SUCCESS"
    match = re.search(r"\[(\d+)\]", parts[2])

    event["hostname"] = parts[1]

    if match:
        event["pid"] = int(match.group(1))
    match = re.search(r"(\w+)\[\d+\]", parts[2])
    event["service"] = match.group(1)
    if event["service"] == "sudo":
        match = re.search(r"(\w+) : .*COMMAND=(.*?) event=SUDO_COMMAND", line)

        if match:
            event["username"] = match.group(1)
            event["command"] = match.group(2)
            event["event_type"] = "SUDO_COMMAND"
    if event["service"] == "nginx":
        match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)

        if match:
            event["source_ip"] = match.group(1)
    if event["service"] == "postgres":
        match = re.search(r"user=(\w+)", line)

        if match:
            event["username"] = match.group(1)

        match = re.search(r"database=(\w+)", line)

        if match:
            event["database"] = match.group(1)

        match = re.search(r"source=(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", line)

        if match:
            event["source_ip"] = match.group(1)
            event["source_port"] = int(match.group(2))

        match = re.search(r"event=(\S+)", line)

        if match:
            event["event_type"] = match.group(1)
    match = re.search(r'"\w+ .*? HTTP/\d\.\d" (\d{3})', line)

    if match:
        event["status_code"] = int(match.group(1))  
    if "Failed password" in line:
        event["event_type"] = "LOGIN_FAILURE"

    elif "event=AUTH_SUCCESS" in line:
        event["event_type"] = "LOGIN_SUCCESS"

    elif "event=AUTH_DISCONNECT" in line:
        event["event_type"] = "LOGIN_DISCONNECT"
    return event