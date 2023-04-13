import socket
import subprocess
import geoip2
import psutil
from geoip2.database import Reader
from modules import log, output_result


def get_network_connections():
    connections = []

    for conn in psutil.net_connections(kind='inet'):
        local_address = conn.laddr.ip + ':' + str(conn.laddr.port)
        remote_address = '-'
        if conn.raddr:
            remote_address = conn.raddr.ip + ':' + str(conn.raddr.port)

        connections.append({
            'fd': conn.fd,
            'family': socket.AddressFamily(conn.family).name,
            'type': socket.SocketKind(conn.type).name,
            'local_address': local_address,
            'remote_address': remote_address,
            'status': conn.status,
            'pid': conn.pid
        })

    return connections


# 获得境外IP
def get_foreign_connections(local_country_code='CN'):
    # IP地理位置数据库
    db_path = "./data/GeoLite2-Country.mmdb"
    geoip_reader = Reader(db_path)

    foreign_connections = []

    # Get network connections using 'ss' command
    output = subprocess.check_output(['ss', '-ntu']).decode('utf-8')
    lines = output.strip().split('\n')

    for line in lines[1:]:
        parts = line.split()
        remote_address = parts[4].split(':')[0]
        remote_port = parts[4].split(':')[1]

        try:
            ip = socket.gethostbyname(remote_address)
            response = geoip_reader.country(ip)

            if response.country.iso_code != local_country_code:
                foreign_connections.append((ip, remote_port, response.country.name))
        except (socket.gaierror, KeyError, geoip2.errors.AddressNotFoundError):
            pass

    geoip_reader.close()

    return foreign_connections


def load_malicious_ips(file_path):
    with open(file_path, "r") as f:
        malicious_ips = [line.strip().split()[0] for line in f.readlines() if line.strip() and len(line.strip().split()) > 0]
    return set(malicious_ips)


def get_active_connections():
    active_connections = []

    output = subprocess.check_output(['ss', '-ntu']).decode('utf-8')
    lines = output.strip().split('\n')

    for line in lines[1:]:
        parts = line.split()
        remote_address = parts[4].split(':')[0]
        remote_port = parts[4].split(':')[1]

        active_connections.append((remote_address, remote_port))

    return active_connections


# 检测已知数据库中的恶意IP
def detect_malicious_connections():
    # 恶意IP数据库
    malicious_ips = load_malicious_ips("./data/ip_reputation_generic.txt")

    connections = get_active_connections()

    malicious_connections = []

    for conn in connections:
        ip = conn[0]
        if ip in malicious_ips:
            malicious_connections.append(conn)

    return malicious_connections


def main():
    # 获取所有连接详情
    connections = get_network_connections()
    for conn in connections:
        output_result.write_content("connections.txt", f"fd: {conn['fd']}")
        output_result.write_content("connections.txt", f"family: {conn['family']}")
        output_result.write_content("connections.txt", f"type: {conn['type']}")
        output_result.write_content("connections.txt", f"local_address: {conn['local_address']}")
        output_result.write_content("connections.txt", f"remote_address: {conn['remote_address']}")
        output_result.write_content("connections.txt", f"status: {conn['status']}")
        output_result.write_content("connections.txt", f"pid: {conn['pid']}")
        output_result.write_content("connections.txt", "")

    # 检查境外IP
    local_country_code = 'CN'  # Modify this country code if you are not chinese

    foreign_ips = get_foreign_connections(local_country_code)

    if foreign_ips:
        log.print_and_log("Foreign connections:")
        for ip, port, country in foreign_ips:
            log.print_and_log(f"IP: {ip}, Port: {port}, Country: {country}")
    else:
        log.print_and_log("No foreign connections detected.")

    # 检查恶意IP
    malicious_connections = detect_malicious_connections()

    if malicious_connections:
        log.print_and_log("Malicious connections detected:")
        for ip, port in malicious_connections:
            log.print_and_log(f"IP: {ip}, Port: {port}")
    else:
        log.print_and_log("No malicious connections detected.")


if __name__ == "__main__":
    main()
