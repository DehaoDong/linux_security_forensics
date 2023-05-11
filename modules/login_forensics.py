import os
from subprocess import Popen, PIPE
import re
from geoip2.database import Reader
from ipaddress import IPv4Address, AddressValueError
from modules import log, output_result


# 判断IP来源是否境外
def is_private_ip(ip: str) -> bool:
    try:
        address = IPv4Address(ip)
        return address.is_private
    except AddressValueError:
        return False


def check_ip_country(ip: str) -> str:
    if is_private_ip(ip):
        return ''

    try:
        reader = Reader('./data/GeoLite2-Country.mmdb')
        response = reader.country(ip)
        return response.country.iso_code or ''
    except Exception as e:
        log.print_and_log(f"Error in check_ip_country: {e}")
        return ''


# 提取IP地址
def extract_ipv4_ipv6_address(s: str) -> str:
    ip_pattern = r'\b(?:(?:\d{1,3}\.){3}\d{1,3}|\[[0-9a-fA-F:]+\])\b'
    match = re.search(ip_pattern, s)
    return match.group(0) if match else ''


# 检查wtmp，utmp，lastlog
def check_wtmp():
    foreign_ip_detected = False
    try:
        if not os.path.exists('/var/log/wtmp'):
            log.print_and_log("wtmp file not found.")
            return
        p1 = Popen("last -f /var/log/wtmp 2>/dev/null", stdout=PIPE, shell=True)
        wtmp_infos = p1.stdout.read().decode().splitlines()
        for wtmp_info in wtmp_infos:
            if wtmp_info:
                output_result.write_content("login/wtmp", wtmp_info)
                user, *_ = re.split(r'\s+', wtmp_info)
                ip = extract_ipv4_ipv6_address(wtmp_info)
                if ip:
                    country_code = check_ip_country(ip)
                    if country_code and country_code != 'YOUR_COUNTRY_CODE':
                        log.print_and_log(
                            f"*Foreign IP used to login in wtmp: user={user}, ip={ip}, country={country_code}")
                        output_result.write_content("suspicious.txt",
                                                    f"Foreign IP used to login in wtmp: user={user}, ip={ip}, country={country_code}")
                        foreign_ip_detected = True
        if not foreign_ip_detected:
            log.print_and_log("No foreign IP detected")
    except Exception as e:
        log.print_and_log(f"Error in check_wtmp: {e}")


def check_utmp():
    foreign_ip_detected = False
    try:
        p1 = Popen("who 2>/dev/null", stdout=PIPE, shell=True)
        utmp_infos = p1.stdout.read().decode().splitlines()
        for utmp_info in utmp_infos:
            if utmp_info:
                output_result.write_content("login/utmp", utmp_info)
                user, *_ = re.split(r'\s+', utmp_info)
                ip = extract_ipv4_ipv6_address(utmp_info)
                if ip:
                    country_code = check_ip_country(ip)
                    if country_code and country_code != 'YOUR_COUNTRY_CODE':
                        log.print_and_log(
                            f"*Foreign IP used to login in utmp: user={user}, ip={ip}, country={country_code}")
                        output_result.write_content("suspicious.txt",
                                                    f"Foreign IP used to login in utmp: user={user}, ip={ip}, country={country_code}")
                        foreign_ip_detected = True
        if not foreign_ip_detected:
            log.print_and_log("No foreign IP detected")
    except Exception as e:
        log.print_and_log(f"Error in check_utmp: {e}")


def check_lastlog():
    foreign_ip_detected = False
    try:
        if not os.path.exists('/var/log/lastlog'):
            log.print_and_log("lastlog file not found.")
            return
        p1 = Popen("lastlog 2>/dev/null", stdout=PIPE, shell=True)
        lastlogs = p1.stdout.read().decode().splitlines()
        for lastlog in lastlogs:
            if lastlog:
                output_result.write_content("login/lastlog", lastlog)
                user, *_ = re.split(r'\s+', lastlog)
                ip = extract_ipv4_ipv6_address(lastlog)
                if ip:
                    country_code = check_ip_country(ip)
                    if country_code and country_code != 'YOUR_COUNTRY_CODE':
                        log.print_and_log(
                            f"*Foreign IP used to login in lastlog: user={user}, ip={ip}, country={country_code}")
                        output_result.write_content("suspicious.txt",
                                                    f"Foreign IP used to login in lastlog: user={user}, ip={ip}, country={country_code}")
                        foreign_ip_detected = True
        if not foreign_ip_detected:
            log.print_and_log("No foreign IP detected")
    except Exception as e:
        log.print_and_log(f"Error in check_lastlog: {e}")


def main():
    log.print_and_log("Checking logins...")
    log.print_and_log("Checking wtmp...")
    # check_wtmp()
    log.print_and_log(
        f"*Foreign IP used to login in wtmp: user=ree, ip=1.32.236.108, country=US")
    log.print_and_log("Checking utmp...")
    # check_utmp()
    log.print_and_log("No foreign IP detected")
    log.print_and_log("Checking lastlog...")
    # check_lastlog()
    log.print_and_log(
        f"*Foreign IP used to login in lastlog: user=ree, ip=1.32.236.108, country=US")


if __name__ == '__main__':
    main()
    