import socket
import psutil


# 境外IP链接扫描
def check_foreign_ip_connections(country_code="CN"):
    foreign_ip_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            try:
                hostname = socket.gethostbyaddr(conn.raddr[0])[0]
                if not hostname.endswith(f".{country_code}"):
                    foreign_ip_connections.append((conn, hostname))
            except socket.herror:
                pass

    return foreign_ip_connections


# 恶意特征链接扫描
def check_malicious_connections(malicious_keywords):
    malicious_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            try:
                hostname = socket.gethostbyaddr(conn.raddr[0])[0]
                if any(keyword in hostname for keyword in malicious_keywords):
                    malicious_connections.append((conn, hostname))
            except socket.herror:
                pass

    return malicious_connections


def main():
    # 6.1
    foreign_ip_connections = check_foreign_ip_connections()
    if foreign_ip_connections:
        print("Foreign IP connections:")
        for conn, hostname in foreign_ip_connections:
            print(f"{conn.laddr[0]}:{conn.laddr[1]} -> {conn.raddr[0]}:{conn.raddr[1]} ({hostname})")
    else:
        print("No foreign IP connections found.")

    # 6.2
    malicious_keywords = ["malicious", "evil"]  # 根据需要添加更多关键词
    malicious_connections = check_malicious_connections(malicious_keywords)
    if malicious_connections:
        print("\nMalicious connections:")
        for conn, hostname in malicious_connections:
            print(f"{conn.laddr[0]}:{conn.laddr[1]} -> {conn.raddr[0]}:{conn.raddr[1]} ({hostname})")
    else:
        print("\nNo malicious connections found.")


if __name__ == "__main__":
    main()
