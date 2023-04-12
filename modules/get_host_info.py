#  获取主机信息
import os
import socket
import psutil


def get_host_info():
    os_info = os.uname()
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    cpu_info = psutil.cpu_count()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')

    host_info = {
        "os_info": os_info,
        "hostname": hostname,
        "ip_address": ip_address,
        "cpu_info": cpu_info,
        "memory_info": memory_info,
        "disk_info": disk_info
    }

    return host_info


def main():
    # 获取主机信息
    host_info = get_host_info()
    print("Host Info:")
    for key, value in host_info.items():
        print(f"{key}: {value}")


if __name__ == '__main__':
    main()
