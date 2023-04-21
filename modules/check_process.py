import os
import subprocess
import psutil
import re
from modules import log, output_result


# store processes details
def get_process_details():
    process_details = []

    for process in psutil.process_iter():
        try:
            process_info = {
                'name': process.name(),
                'pid': process.pid,
                'ppid': process.ppid(),
                'uid': process.uids().real,
                'create_time': process.create_time(),
                'status': process.status(),
                'priority': process.nice(),
                'cpu_percent': process.cpu_percent(),
                'memory_info': process.memory_info(),
                'cmdline': process.cmdline(),
                'gid': process.gids().real,
                'num_fds': process.num_fds(),
                'environ': process.environ(),
                'cwd': process.cwd(),
                'root': os.readlink(f'/proc/{process.pid}/root') if process.pid != 1 else '/',
                'open_files': [file.path for file in process.open_files()],
                'connections': [conn.laddr._asdict() for conn in process.connections()]
            }
            process_details.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return process_details


def store_processes_details():
    process_details = get_process_details()
    for process_info in process_details:
        for key, value in process_info.items():
            output_result.write_content("processes_details", f"{key}: {value}")
        output_result.write_content("processes_details", "\n")


# CPU和内存使用异常进程排查
def check_high_resource_usage_processes(cpu_threshold=90, memory_threshold=90):
    high_resource_usage_processes = []
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        if process.cpu_percent() > cpu_threshold or process.memory_percent() > memory_threshold:
            high_resource_usage_processes.append(process)

    return high_resource_usage_processes


# 隐藏进程扫描
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

    return hidden_processes


# 反弹shell类进程扫描
def check_reverse_shell_processes():
    with open("./data/reverse_shell_processes_features", 'r') as file:
        lines = file.readlines()

    keywords = []

    for line in lines:
        line = line.strip()
        if not line.startswith('#'):
            keywords.append(line)

    reverse_shell_pattern = re.compile(r'\b(?:' + '|'.join(keywords) + r')\b', re.IGNORECASE)
    reverse_shell_processes = []

    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(process.cmdline())
            if reverse_shell_pattern.search(cmdline) and "java" not in cmdline and "firefox" not in cmdline and not cmdline.startswith("-bash") and not cmdline.startswith("bash") and "pycharm" not in cmdline:
                reverse_shell_processes.append(process)
        except psutil.AccessDenied:
            pass

    return reverse_shell_processes


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


# 检查源文件已被删除的进程
def check_source_deleted_processes():
    running_processes = get_running_processes()
    source_deleted_processes = []

    for pid, comm in running_processes:
        if is_source_deleted(pid):
            source_deleted_processes.append(f"Process {comm} (PID: {pid}) has its source deleted.")

    return source_deleted_processes


def main():
    log.print_and_log("Checking processes...")

    # 存储所有进程详细信息
    store_processes_details()

    # CPU和内存使用异常进程排查
    high_resource_usage_processes = check_high_resource_usage_processes()
    if high_resource_usage_processes:
        log.print_and_log("*High resource usage processes:")
        output_result.write_content("suspicious.txt", "High resource usage processes:")
        for process in high_resource_usage_processes:
            log.print_and_log(f"*{process.pid} {process.name()} CPU: {process.cpu_percent()}% Memory: {process.memory_percent()}%")
            output_result.write_content("suspicious.txt", f"{process.pid} {process.name()} CPU: {process.cpu_percent()}% Memory: {process.memory_percent()}%")
    else:
        log.print_and_log("No high resource usage processes found.")

    # 隐藏进程安全扫描
    hidden_processes = detect_hidden_processes()
    if hidden_processes:
        log.print_and_log("*Hidden processes detected:")
        output_result.write_content("suspicious.txt", "Hidden processes detected:")
        for pid in hidden_processes:
            log.print_and_log(f"*PID: {process.pid}, Name: {process.name()}, Cmdline: {' '.join(process.cmdline())}")
            output_result.write_content("suspicious.txt", f"PID: {process.pid}, Name: {process.name()}, Cmdline: {' '.join(process.cmdline())}")
    else:
        log.print_and_log("No hidden processes detected.")

    # 反弹shell类进程扫描
    reverse_shell_processes = check_reverse_shell_processes()
    if reverse_shell_processes:
        log.print_and_log("*Reverse shell processes:")
        output_result.write_content("suspicious.txt", "Reverse shell processes:")
        for process in reverse_shell_processes:
            log.print_and_log(f"*{process.pid} {process.name()} Cmdline: {' '.join(process.cmdline())}")
            output_result.write_content("suspicious.txt", f"{process.pid} {process.name()} Cmdline: {' '.join(process.cmdline())}")
    else:
        log.print_and_log("No reverse shell processes found.")

    # 扫描源文件已被删除的进程
    source_deleted_processes = check_source_deleted_processes()
    if source_deleted_processes:
        log.print_and_log("*Source deleted processes:")
        output_result.write_content("suspicious.txt", "Source deleted processes:")
        for pid, comm in source_deleted_processes:
            if is_source_deleted(pid):
                log.print_and_log(f"*Process {comm} (PID: {pid}) has its source deleted.")
                output_result.write_content("suspicious.txt", f"Process {comm} (PID: {pid}) has its source deleted.")
    else:
        log.print_and_log("No source deleted processes found")


if __name__ == "__main__":
    main()
