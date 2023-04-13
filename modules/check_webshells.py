import os
import re
import glob
from modules import log, output_result


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
                            log.print_and_log(f"Possible WebShell found: {file_path}")
                            break


def main():
    log.print_and_log("Checking web servers...")
    # 提取web服务器的web目录
    web_server_directories = load_web_server_directories("./data/server_directories")
    for server_name, web_directory in web_server_directories.items():
        if '*' in web_directory:
            for directory in glob.glob(web_directory.replace('*', '*')):
                log.print_and_log(f"\nScanning {server_name} web directory '{directory}' for WebShells:")
                scan_web_directory_for_webshells(directory)
        elif os.path.exists(web_directory):
            log.print_and_log(f"\nScanning {server_name} web directory '{web_directory}' for WebShells:")
            scan_web_directory_for_webshells(web_directory)
        else:
            log.print_and_log(f"\n{server_name} web directory '{web_directory}' not found.")


if __name__ == "__main__":
    main()
    