import os
import subprocess
import psutil
import re


# CPU和内存使用异常进程排查
def check_high_resource_usage_processes(cpu_threshold=90, memory_threshold=90):
    high_resource_usage_processes = []
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        if process.info['cpu_percent'] > cpu_threshold or process.info['memory_percent'] > memory_threshold:
            high_resource_usage_processes.append(process)

    return high_resource_usage_processes


# 隐藏进程安全扫描
def get_ps_processes():
    output = subprocess.check_output(["ps", "-eo", "pid"]).decode("utf-8")
    lines = output.strip().split('\n')
    pids = [int(line) for line in lines[1:]]
    return set(pids)


def get_proc_processes():
    pids = set()
    for entry in os.scandir('/proc'):
        if entry.is_dir() and entry.name.isdigit():
            pids.add(int(entry.name))
    return pids


def detect_hidden_processes():
    ps_processes = get_ps_processes()
    proc_processes = get_proc_processes()

    hidden_processes = proc_processes - ps_processes

    if hidden_processes:
        print("Hidden processes detected:")
        for pid in hidden_processes:
            print(f"PID: {pid}")
    else:
        print("No hidden processes detected.")


# 反弹shell类进程扫描
def check_reverse_shell_processes():
    reverse_shell_pattern = re.compile(r'(nc|netcat|socat|bash).*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*(\d{1,5})')
    reverse_shell_processes = []

    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(process.info['cmdline'])
            if reverse_shell_pattern.search(cmdline):
                reverse_shell_processes.append(process)
        except psutil.AccessDenied:
            pass

    return reverse_shell_processes


# 恶意进程信息安全扫描
def check_malicious_processes(malicious_keywords):
    malicious_processes = []
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(process.info['cmdline'])
            if any(keyword in cmdline for keyword in malicious_keywords):
                malicious_processes.append(process)
        except psutil.AccessDenied:
            pass

    return malicious_processes


def get_running_processes():
    output = subprocess.check_output(["ps", "-eo", "pid,comm"]).decode("utf-8")
    lines = output.strip().split('\n')
    processes = []
    for line in lines[1:]:
        pid, comm = line.split(maxsplit=1)
        processes.append((int(pid), comm))
    return processes


def is_source_deleted(pid):
    try:
        exe_path = os.readlink(f'/proc/{pid}/exe')
        if ' (deleted)' in exe_path:
            return True
    except FileNotFoundError:
        pass
    return False


def main():
    # CPU和内存使用异常进程排查
    high_resource_usage_processes = check_high_resource_usage_processes()
    if high_resource_usage_processes:
        print("High resource usage processes:")
        for process in high_resource_usage_processes:
            print(f"{process.info['pid']} {process.info['name']} CPU: {process.info['cpu_percent']}% Memory: {process.info['memory_percent']}%")
    else:
        print("No high resource usage processes found.")

    # 隐藏进程安全扫描
    print("\nHidden processes:")
    detect_hidden_processes()

    # 反弹shell类进程扫描
    reverse_shell_processes = check_reverse_shell_processes()
    if reverse_shell_processes:
        print("\nReverse shell processes:")
        for process in reverse_shell_processes:
            print(f"{process.info['pid']} {process.info['name']} Cmdline: {' '.join(process.info['cmdline'])}")
    else:
        print("\nNo reverse shell processes found.")

    # 恶意进程信息安全扫描
    malicious_keywords = ["malware", "ransomware", "keylogger"]  # unfinished!!!!
    malicious_processes = check_malicious_processes(malicious_keywords)
    if malicious_processes:
        print("\nMalicious processes:")
        for process in malicious_processes:
            print(f"{process.info['pid']} {process.info['name']} Cmdline: {' '.join(process.info['cmdline'])}")
    else:
        print("\nNo malicious processes found.")

    # 扫描源文件已被删除的进程
    print("\nSource deleted processes:")
    running_processes = get_running_processes()
    for pid, comm in running_processes:
        if is_source_deleted(pid):
            print(f"Process {comm} (PID: {pid}) has its source deleted.")


if __name__ == "__main__":
    main()
