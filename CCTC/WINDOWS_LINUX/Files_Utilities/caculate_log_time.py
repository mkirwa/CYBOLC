import re
from datetime import datetime

def parse_log_line(line):
    """ Parse a single line of the log file to extract the timestamp, username, and event type (login/logout). """
    timestamp_format = "%b %d %H:%M:%S"
    login_regex = r"(\w+ \d+ \d+:\d+:\d+).*Accepted password for (\w+)"
    logout_regex = r"(\w+ \d+ \d+:\d+:\d+).*Disconnected from user (\w+)"

    if "Accepted password for" in line:
        match = re.search(login_regex, line)
        event_type = 'login'
    elif "Disconnected from user" in line:
        match = re.search(logout_regex, line)
        event_type = 'logout'
    else:
        return None

    if match:
        timestamp_str, user = match.groups()
        timestamp = datetime.strptime(timestamp_str, timestamp_format)
        return user, timestamp, event_type
    else:
        return None

def calculate_logged_time(log_lines):
    """ Calculate the total logged in time for each user from the log lines. """
    user_sessions = {}
    for line in log_lines:
        parsed_line = parse_log_line(line)
        if parsed_line:
            user, timestamp, event_type = parsed_line
            if user not in user_sessions:
                user_sessions[user] = {'login': [], 'logout': []}
            user_sessions[user][event_type].append(timestamp)

    # Calculate total logged in time
    total_time = {}
    for user, times in user_sessions.items():
        total_login_time = sum((logout - login).total_seconds() for login, logout in zip(times['login'], times['logout']))
        total_time[user] = total_login_time

    return total_time

# Example usage:
log_lines = [
    "Apr 6 00:00:01 linux-opstation-7qhp sshd[11308]: Accepted password for Frodo from 192.168.242.166 port 48558 ssh2",
    "Apr 6 01:15:02 linux-opstation-7qhp[3915]: Disconnected from user Frodo 192.168.242.166 port 48558"
]

total_time = calculate_logged_time(log_lines)
for user, time in total_time.items():
    print(f"User {user} was logged in for {time} seconds.")
