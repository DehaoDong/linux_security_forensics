import os
import subprocess


# 获取所有网络接口
def get_network_interfaces():
    output = subprocess.check_output(["ip", "link", "show"]).decode("utf-8")
    interfaces = []
    for line in output.split("\n"):
        if "mtu" in line:
            interface = line.split(":")[1].strip()
            interfaces.append(interface)
    return interfaces


# 断网隔离主机
def disable_network_interfaces(interfaces):
    for interface in interfaces:
        print(f"Disabling {interface}...")
        os.system(f"sudo ip link set {interface} down")
        print(f"{interface} is disabled.")


def main():
    interfaces = get_network_interfaces()
    disable_network_interfaces(interfaces)
    print("All network interfaces have been disabled.")


if __name__ == "__main__":
    main()
