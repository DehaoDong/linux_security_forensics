import os
import re
import glob
import subprocess

from modules import log, output_result


# 备份服务器日志
def read_log_directories(file_path):
    log_directories = {}
    with open(file_path, 'r') as f:
        for line in f.readlines():
            server_name, log_directory = line.strip().split(',', 1)
            log_directories[server_name] = log_directory
    return log_directories


def backup_logs(server_name, log_directories):
    for log_directory in log_directories:
        if os.path.exists(log_directory):
            backup_path = f"server_logs/{server_name}_log.txt"

            for filename in os.listdir(log_directory):
                # 添加过滤条件，只备份 .log 文件
                if not filename.endswith('.log'):
                    continue

                log_file = os.path.join(log_directory, filename)
                output_result.write_content(backup_path, log_file)
            log.print_and_log(f"Backed up {server_name} logs from {log_directory} to {backup_path}")
        else:
            log.print_and_log(f"{server_name} log directory '{log_directory}' not found.")


# 从文件中加载WebShell特征
def load_webshell_signatures(file_path):
    with open(file_path, 'r') as f:
        signatures = [line.strip() for line in f.readlines()]
    return signatures


# 从文件中加载web服务器目录
def load_web_server_directories(file_path):
    with open(file_path, 'r') as f:
        directories = {line.strip().split(',')[0]: line.strip().split(',')[1] for line in f.readlines()}
    return directories


def scan_web_directory_for_webshells(directory):
    # 已知的WebShell特征
    webshell_signatures = load_webshell_signatures("./data/webshell_signatures")
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            if file.endswith(('.php', '.aspx', '.jsp', '.pl')):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for signature in webshell_signatures:
                        if re.search(signature, content, re.IGNORECASE):
                            log.print_and_log(f"*Possible WebShell found: {file_path}")
                            output_result.write_content("suspicious.txt", f"Possible WebShell found: {file_path}")
                            break


def main():
    log.print_and_log("Checking web servers...")

    log.print_and_log("Backing up server logs...")
    # 备份服务器日志
    log_directories_file = "./data/server_logs"
    log_directories = read_log_directories(log_directories_file)

    for server_name, log_directory in log_directories.items():
        expanded_log_directory = []
        if isinstance(log_directory, str) and "*" in log_directory:
            expanded_log_directory = glob.glob(log_directory)
        elif isinstance(log_directory, list):
            temp = []
            for ld in log_directory:
                if "*" in ld:
                    temp.extend(glob.glob(ld))
                else:
                    temp.append(ld)
            expanded_log_directory = temp
        else:
            expanded_log_directory = [log_directory]

        backup_logs(server_name, expanded_log_directory)

        # log.print_and_log(subprocess.run(['du', '-sh', 'results/'], capture_output=True, text=True).stdout)

    log.print_and_log("server logs backup completed")
    log.print_and_log("Checking webshells...")

    # 提取web服务器的web目录
    web_server_directories = load_web_server_directories("./data/server_directories")
    for server_name, web_directory in web_server_directories.items():
        if '*' in web_directory:
            for directory in glob.glob(web_directory.replace('*', '*')):
                log.print_and_log(f"Scanning {server_name} web directory '{directory}' for WebShells:")
                scan_web_directory_for_webshells(directory)
        elif os.path.exists(web_directory):
            log.print_and_log(f"Scanning {server_name} web directory '{web_directory}' for WebShells:")
            scan_web_directory_for_webshells(web_directory)
        else:
            log.print_and_log(f"{server_name} web directory '{web_directory}' not found.")


if __name__ == "__main__":
    main()
    