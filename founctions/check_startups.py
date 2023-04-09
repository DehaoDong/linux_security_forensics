import os
import glob


def check_startup_items():
    # 系统启动项路径
    startup_paths = [
        '/etc/rc.d',
        '/etc/rc.local',
        '/etc/init.d',
        '/etc/systemd/system'
    ]

    # 可疑关键词（可根据需要添加更多关键词）
    suspicious_keywords = ['malicious', 'evil', 'harmful']

    found_issues = []

    for path in startup_paths:
        if os.path.isfile(path):
            with open(path) as f:
                for line_number, line in enumerate(f, start=1):
                    if any(keyword in line for keyword in suspicious_keywords):
                        found_issues.append((path, line_number, line.strip()))
        elif os.path.isdir(path):
            for startup_file in glob.glob(os.path.join(path, '*')):
                if os.path.isfile(startup_file):
                    with open(startup_file) as f:
                        for line_number, line in enumerate(f, start=1):
                            if any(keyword in line for keyword in suspicious_keywords):
                                found_issues.append((startup_file, line_number, line.strip()))

    return found_issues


if __name__ == "__main__":
    issues = check_startup_items()

    if issues:
        print("Found potential issues in startup items:")
        for issue in issues:
            print(f"File: {issue[0]}, Line: {issue[1]}, Content: {issue[2]}")
    else:
        print("No issues found in startup items.")
