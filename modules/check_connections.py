import os
import socket
import subprocess

import geoip2
from geoip2.database import Reader


def get_foreign_connections(local_country_code='CN'):
    db_path = "../data/GeoLite2-Country.mmdb"
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


def detect_malicious_connections(connections, malicious_ips):
    malicious_connections = []

    for conn in connections:
        ip = conn[0]
        if ip in malicious_ips:
            malicious_connections.append(conn)

    return malicious_connections


if __name__ == "__main__":
    local_country_code = 'CN'  # Change this to the local country code, e.g., 'US' for the United States

    foreign_ips = get_foreign_connections(local_country_code)

    if foreign_ips:
        print("Foreign connections:")
        for ip, port, country in foreign_ips:
            print(f"IP: {ip}, Port: {port}, Country: {country}")
    else:
        print("No foreign connections detected.")

    malicious_ips = load_malicious_ips("../data/ip_reputation_generic.txt")
    active_connections = get_active_connections()

    malicious_connections = detect_malicious_connections(active_connections, malicious_ips)

    if malicious_connections:
        print("Malicious connections detected:")
        for ip, port in malicious_connections:
            print(f"IP: {ip}, Port: {port}")
    else:
        print("No malicious connections detected.")
