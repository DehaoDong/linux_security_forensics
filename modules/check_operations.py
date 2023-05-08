import os
import re
import glob
import geoip2.database

from modules import log, output_result


# 境外IP操作类
def check_foreign_ip_operations(history_files, geoip_db_path):
    foreign_ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    foreign_ip_operations = []

    # 创建GeoIP Reader实例
    with geoip2.database.Reader(geoip_db_path) as reader:
        for file in history_files:
            log.print_and_log(f"Checking {file} for foreign IP operations")
            with open(file, 'r') as history_file:
                lines = history_file.readlines()
                for line in lines:
                    match = foreign_ip_pattern.search(line)
                    if match:
                        ip = match.group(0)
                        try:
                            response = reader.country(ip)
                            if response.country.iso_code != 'CN':
                                foreign_ip_operations.append(line.strip())
                        except geoip2.errors.AddressNotFoundError:
                            pass

    return foreign_ip_operations


# 反弹shell类
def check_reverse_shell_operations(history_files):
    reverse_shell_pattern = re.compile(r'(nc|netcat|socat|bash).*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*(\d{1,5})')
    reverse_shell_operations = []

    for file in history_files:
        log.print_and_log(f"Checking {file} for reverse shell operations")
        with open(file, 'r') as history_file:
            lines = history_file.readlines()
            for line in lines:
                if reverse_shell_pattern.search(line):
                    reverse_shell_operations.append(line.strip())

    return reverse_shell_operations


def main():
    log.print_and_log("Checking operations...")

    # 获取用户目录
    user_dirs = glob.glob('/home/*')

    # 获取所有用户的.bash_history文件
    history_files = [os.path.join(user_dir, '.bash_history') for user_dir in user_dirs]
    # 添加root用户的.bash_history文件
    root_history_file = '/root/.bash_history'
    if os.path.exists(root_history_file):
        history_files.append(root_history_file)

    for history_file in history_files:
        output_result.write_content(f"operations/{history_file.replace('/', '_')}", history_file)

    # 检查境外IP操作
    geoip_db_path = './data/GeoLite2-Country.mmdb'
    foreign_ip_operations = check_foreign_ip_operations(history_files, geoip_db_path)
    if foreign_ip_operations:
        log.print_and_log("*Foreign IP operations found:")
        output_result.write_content("suspicious.txt", "Foreign IP operations found:")
        for operation in foreign_ip_operations:
            log.print_and_log(f"*{operation}")
            output_result.write_content("suspicious.txt", operation)
    else:
        log.print_and_log("No foreign IP operations found.")

    # 检查反弹shell操作
    reverse_shell_operations = check_reverse_shell_operations(history_files)
    if reverse_shell_operations:
        log.print_and_log("*Reverse shell operations found:")
        output_result.write_content("suspicious.txt", "Reverse shell operations found:")
        for operation in reverse_shell_operations:
            log.print_and_log(f"*{operation}")
            output_result.write_content("suspicious.txt", operation)
    else:
        log.print_and_log("No reverse shell operations found.")


if __name__ == "__main__":
    main()
