import os
import subprocess


def get_running_processes():
    output = subprocess.check_output(["ps", "-eo", "pid,comm"]).decode("utf-8")
    lines = output.strip().split('\n')
    processes = []
    for line in lines[1:]:
        pid, comm = line.split()
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
    running_processes = get_running_processes()
    for pid, comm in running_processes:
        if is_source_deleted(pid):
            print(f"Process {comm} (PID: {pid}) has its source deleted.")


if __name__ == "__main__":
    main()
