import os
import re
import glob


# 境外IP操作类
def check_foreign_ip_operations(history_files):
    foreign_ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    foreign_ip_operations = []

    for file in history_files:
        with open(file, 'r') as history_file:
            lines = history_file.readlines()
            for line in lines:
                if foreign_ip_pattern.search(line):
                    foreign_ip_operations.append(line.strip())

    return foreign_ip_operations


# 反弹shell类
def check_reverse_shell_operations(history_files):
    reverse_shell_pattern = re.compile(r'(nc|netcat|socat|bash).*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*(\d{1,5})')
    reverse_shell_operations = []

    for file in history_files:
        with open(file, 'r') as history_file:
            lines = history_file.readlines()
            for line in lines:
                if reverse_shell_pattern.search(line):
                    reverse_shell_operations.append(line.strip())

    return reverse_shell_operations


def main():
    # 获取用户目录
    user_dirs = glob.glob('/home/*')

    # 获取所有用户的.bash_history文件
    history_files = [os.path.join(user_dir, '.bash_history') for user_dir in user_dirs]

    # 检查境外IP操作
    foreign_ip_operations = check_foreign_ip_operations(history_files)
    if foreign_ip_operations:
        print("Foreign IP operations found:")
        for operation in foreign_ip_operations:
            print(operation)
    else:
        print("No foreign IP operations found.")

    # 检查反弹shell操作
    reverse_shell_operations = check_reverse_shell_operations(history_files)
    if reverse_shell_operations:
        print("\nReverse shell operations found:")
        for operation in reverse_shell_operations:
            print(operation)
    else:
        print("\nNo reverse shell operations found.")


if __name__ == "__main__":
    main()
