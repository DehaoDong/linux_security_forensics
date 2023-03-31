import os
import re
import datetime

# 登陆日志分析
def analyze_login_logs(log_file='/var/log/auth.log'):
    login_attempts = []

    if os.path.isfile(log_file):
        with open(log_file) as f:
            for line in f:
                match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+.*\s+sshd\[\d+\]:\s+'
                                  r'(Accepted|Failed)\s+password\s+.*\s+for\s+(\S+)', line)
                if match:
                    timestamp = datetime.datetime.strptime(match.group(1), '%b %d %H:%M:%S').replace(
                        year=datetime.datetime.now().year)
                    result = match.group(2)
                    user = match.group(3)
                    login_attempts.append((timestamp, result, user))

    return login_attempts

def main():
    print("Login attempts:")
    for timestamp, result, user in analyze_login_logs():
        print(f"{timestamp}: {result} password for {user}")

if __name__ == "__main__":
    main()
