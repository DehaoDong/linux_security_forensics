import os
import stat
import re

from modules import output_result, log


# 检测非标准或意外的目录
def check_directory(path):
    standard_directories = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system']
    return path not in standard_directories


# 检测不寻常的权限设置
def check_unusual_permissions(filepath):
    file_stat = os.stat(filepath)
    executable = bool(file_stat.st_mode & stat.S_IXUSR)
    readable = bool(file_stat.st_mode & stat.S_IRUSR)
    return executable and not readable


# 检测是否试图隐藏行为
def check_hidden_behavior(filepath):
    with open(filepath, 'r') as file:
        content = file.read()
        if re.search(r'>\s*/dev/null', content) and re.search(r'\bnohup\b', content) and re.search(r'\s&\s*$', content):
            return True
    return False


# 主函数
def main():
    log.print_and_log("Checking startups...")
    directories_to_check = ['/etc/init.d', '/etc/rc.d', '/etc/systemd/system']

    for directory in directories_to_check:
        if not os.path.exists(directory):
            continue

        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)

            log.print_and_log(f"Checking {file_path}")
            # 备份
            output_result.write_content(f"startups/{file_path.replace('/', '_')}", file_path)

            if os.path.isfile(file_path):
                if check_directory(directory):
                    log.print_and_log(f"*Non-standard directory: {file_path}: {directory}")
                    output_result.write_content("suspicious.txt", f"Non-standard directory: {file_path}: {directory}")

                if check_unusual_permissions(file_path):
                    log.print_and_log(f"*Unusual permissions: {file_path}")
                    output_result.write_content("suspicious.txt", f"Unusual permissions: {file_path}")

                if check_hidden_behavior(file_path):
                    log.print_and_log(f"*Hidden behavior: {file_path}")
                    output_result.write_content("suspicious.txt", f"Hidden behavior: {file_path}")


if __name__ == "__main__":
    main()
