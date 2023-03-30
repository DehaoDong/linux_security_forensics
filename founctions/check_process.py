import os
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
def check_hidden_processes():
    hidden_processes = []
    for process in psutil.process_iter(['pid', 'name']):
        try:
            cmdline = process.cmdline()
            if not cmdline:
                hidden_processes.append(process)
        except psutil.AccessDenied:
            pass

    return hidden_processes


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
    # hidden_processes = check_hidden_processes()
    # if hidden_processes:
    #     print("\nHidden processes:")
    #     for process in hidden_processes:
    #         print(f"{process.info['pid']} {process.info['name']}")
    # else:
    #     print("\nNo hidden processes found.")

    # 反弹shell类进程扫描
    reverse_shell_processes = check_reverse_shell_processes()
    if reverse_shell_processes:
        print("\nReverse shell processes:")
        for process in reverse_shell_processes:
            print(f"{process.info['pid']} {process.info['name']} Cmdline: {' '.join(process.info['cmdline'])}")
    else:
        print("\nNo reverse shell processes found.")

    # 恶意进程信息安全扫描
    malicious_keywords = ["malware", "ransomware", "keylogger"]  # 根据需要添加更多关键词
    malicious_processes = check_malicious_processes(malicious_keywords)
    if malicious_processes:
        print("\nMalicious processes:")
        for process in malicious_processes:
            print(f"{process.info['pid']} {process.info['name']} Cmdline: {' '.join(process.info['cmdline'])}")
    else:
        print("\nNo malicious processes found.")


if __name__ == "__main__":
    main()
