import os
import re
import glob
import pwd


# 各种环境变量后门检测
def check_environment_variable_backdoors():
    backdoor_variables = ['LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH', 'PROMPT_COMMAND']
    found_backdoors = []

    for var in backdoor_variables:
        if var in os.environ:
            found_backdoors.append((var, os.environ[var]))

    return found_backdoors


# Cron后门检测
def check_cron_backdoors():
    cron_paths = ['/etc/crontab', '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.monthly', '/etc/cron.weekly']
    malicious_keywords = ["malicious", "evil"]  # 根据需要添加更多关键词
    found_backdoors = []

    for path in cron_paths:
        if os.path.isfile(path):
            with open(path) as f:
                for line_number, line in enumerate(f, start=1):
                    if any(keyword in line for keyword in malicious_keywords):
                        found_backdoors.append((path, line_number, line.strip()))
        elif os.path.isdir(path):
            for cron_file in glob.glob(os.path.join(path, '*')):
                with open(cron_file) as f:
                    for line_number, line in enumerate(f, start=1):
                        if any(keyword in line for keyword in malicious_keywords):
                            found_backdoors.append((cron_file, line_number, line.strip()))

    return found_backdoors


# Alias后门
def check_alias_backdoors():
    found_backdoors = []

    for line in os.popen('alias'):
        if 'malicious' in line or 'evil' in line:  # 根据需要添加更多关键词
            found_backdoors.append(line.strip())

    return found_backdoors


# SSH 后门检测
def check_ssh_backdoors():
    ssh_config_files = ['/etc/ssh/sshd_config', '/etc/ssh/ssh_config']
    malicious_keywords = ["malicious", "evil"]  # 根据需要添加更多关键词
    found_backdoors = []

    for config_file in ssh_config_files:
        if os.path.isfile(config_file):
            with open(config_file) as f:
                for line_number, line in enumerate(f, start=1):
                    if any(keyword in line for keyword in malicious_keywords):
                        found_backdoors.append((config_file, line_number, line.strip()))

    return found_backdoors


# 系统配置文件后门检测
def check_system_config_backdoors():
    config_files = ['/etc/inetd.conf', '/etc/xinetd.conf']
    malicious_keywords = ["malicious", "evil"]  # 根据需要添加更多关键词
    found_backdoors = []

    for config_file in config_files:
        if os.path.isfile(config_file):
            with open(config_file) as f:
                for line_number, line in enumerate(f, start=1):
                    if any(keyword in line for keyword in malicious_keywords):
                        found_backdoors.append((config_file, line_number, line.strip()))

    return found_backdoors


# setUID后门检测
def resolve_symlink(filepath):
    while os.path.islink(filepath):
        try:
            filepath = os.readlink(filepath)
        except FileNotFoundError:
            break
    return filepath


def check_setuid_backdoors():
    suspicious_files = []
    setuid_files = []

    for root, dirs, files in os.walk('/', followlinks=False):
        for file in files:
            filepath = os.path.join(root, file)
            filepath = resolve_symlink(filepath)
            try:
                file_stat = os.stat(filepath)
                if file_stat.st_mode & os.path.stat.S_ISUID:
                    setuid_files.append(filepath)
                    if file_stat.st_uid != 0:
                        suspicious_files.append(filepath)
            except FileNotFoundError:
                pass

    return suspicious_files, setuid_files


# 系统启动项后门检测
def check_startup_backdoors():
    startup_paths = ['/etc/rc.d', '/etc/rc.local', '/etc/init.d', '/etc/systemd/system']
    malicious_keywords = ["malicious", "evil"]  # 根据需要添加更多关键词
    found_backdoors = []

    for path in startup_paths:
        if os.path.isfile(path):
            with open(path) as f:
                for line_number, line in enumerate(f, start=1):
                    if any(keyword in line for keyword in malicious_keywords):
                        found_backdoors.append((path, line_number, line.strip()))
        elif os.path.isdir(path):
            for startup_file in glob.glob(os.path.join(path, '*')):
                if os.path.isfile(startup_file):
                    with open(startup_file) as f:
                        for line_number, line in enumerate(f, start=1):
                            if any(keyword in line for keyword in malicious_keywords):
                                found_backdoors.append((startup_file, line_number, line.strip()))

    return found_backdoors


def main():
    # 各种后门检测示例
    print("Environment variable backdoors:")
    for var, value in check_environment_variable_backdoors():
        print(f"{var}: {value}")
    print("\nCron backdoors:")
    for path, line_number, line in check_cron_backdoors():
        print(f"{path} (line {line_number}): {line}")

    print("\nAlias backdoors:")
    for alias in check_alias_backdoors():
        print(alias)

    print("\nSSH backdoors:")
    for config_file, line_number, line in check_ssh_backdoors():
        print(f"{config_file} (line {line_number}): {line}")

    print("\nSystem config backdoors:")
    for config_file, line_number, line in check_system_config_backdoors():
        print(f"{config_file} (line {line_number}): {line}")

    print("\nSetUID backdoors:")
    suspicious_files, setuid_files = check_setuid_backdoors()
    print(f"Suspicious SetUID files: {', '.join(suspicious_files)}")
    print(f"Total SetUID files: {len(setuid_files)}")

    print("\nStartup backdoors:")
    for startup_file, line_number, line in check_startup_backdoors():
        print(f"{startup_file} (line {line_number}): {line}")


if __name__ == "__main__":
    main()
