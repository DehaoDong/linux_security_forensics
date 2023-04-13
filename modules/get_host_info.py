import os
import platform
import socket
import multiprocessing
import psutil


def get_os_info():
    os_info = platform.uname()
    return {
        "Operating System": os_info.system,
        "Node Name": os_info.node,
        "Release": os_info.release,
        "Version": os_info.version,
        "Machine": os_info.machine,
        "Processor": os_info.processor,
    }


def get_ip_address():
    ip_address = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except OSError:
        pass

    return {"IP Address": ip_address}


def get_cpu_info():
    cpu_count = multiprocessing.cpu_count()
    return {"CPU Cores": cpu_count}


def get_memory_info():
    mem_info = psutil.virtual_memory()
    total_memory = mem_info.total / (1024 ** 3)
    return {"Total Memory": f"{total_memory:.2f} GB"}


def get_disk_info():
    disk_info = psutil.disk_usage('/')
    total_disk_space = disk_info.total / (1024 ** 3)
    return {"Total Disk Space": f"{total_disk_space:.2f} GB"}


def get_host_info():
    host_info = {}
    host_info.update(get_os_info())
    host_info.update(get_ip_address())
    host_info.update(get_cpu_info())
    host_info.update(get_memory_info())
    host_info.update(get_disk_info())
    return host_info


if __name__ == "__main__":
    host_info = get_host_info()
    for key, value in host_info.items():
        print(f"{key}: {value}")
