import os
import platform

from modules import log, output_result


def read_ssh_logs():
    system_name = platform.system().lower()

    if system_name == 'linux':
        if os.path.exists('/var/log/auth.log'):
            log_file = '/var/log/auth.log'
        elif os.path.exists('/var/log/secure'):
            log_file = '/var/log/secure'
        else:
            log_file = None
    else:
        log_file = None

    if log_file and os.path.isfile(log_file):
        with open(log_file, 'r') as f:
            ssh_logs = f.readlines()
    else:
        ssh_logs = []

    output_result.write_content("ssh_logs.txt", ssh_logs)
    # print(ssh_logs)
    return ssh_logs


def analyze_log(log_lines):
    failed_login_attempts = {}
    successful_logins = []
    suspicious_logins = []

    # 超过这么多次登录判定为可疑
    suspicious_login_times = 20

    for line in log_lines:
        if "sshd" in line:
            parts = line.split()
            if "Failed password for" in line:
                ip = parts[-4]
                failed_login_attempts[ip] = failed_login_attempts.get(ip, 0) + 1
            elif "Accepted password for" in line:
                user = parts[8]
                ip = parts[-4]
                timestamp = " ".join(parts[:3])
                successful_logins.append({"user": user, "ip": ip, "timestamp": timestamp})

    for login in successful_logins:
        if failed_login_attempts.get(login["ip"], 0) > suspicious_login_times:
            suspicious_logins.append(login)

    return suspicious_logins


def main():
    log.print_and_log("Checking SSH...")

    ssh_logs = read_ssh_logs()
    suspicious_logins = analyze_log(ssh_logs)

    if suspicious_logins:
        log.print_and_log("*Suspicious SSH logins found:")
        output_result.write_content("suspicious.txt", "Suspicious SSH logins found:")
        for login in suspicious_logins:
            log.print_and_log(f"*User: {login['user']}, IP: {login['ip']}, Timestamp: {login['timestamp']}")
            output_result.write_content("suspicious.txt", f"User: {login['user']}, IP: {login['ip']}, Timestamp: {login['timestamp']}")
    else:
        log.print_and_log("No suspicious SSH logins found.")


if __name__ == "__main__":
    main()
