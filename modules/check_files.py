import os

from modules import log, output_result


# 系统文件可执行性扫描
def check_executable_files(path):
    for root, _, files in os.walk(path):
        for file in files:
            if not os.access(os.path.join(root, file), os.X_OK):
                output_result.write_content("suspicious.txt", f"non-executable: {os.path.join(root, file)}")
                log.print_and_log(f"non-executable: {os.path.join(root, file)}")


# 临时目录文件安全扫描
def check_temp_directory(path):
    # 检查具有可执行性的临时文件
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.X_OK):
                output_result.write_content("suspicious.txt", f"临时文件 {file_path} 可被执行！")
                log.print_and_log(f"临时文件 {file_path} 可被执行！")

    # 检查大文件
    max_size = 10 * 1024 * 1024  # 10MB
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                output_result.write_content("suspicious.txt", f"临时文件 {file_path} 过大！（超过 {max_size} 字节）")
                log.print_and_log(f"临时文件 {file_path} 过大！（超过 {max_size} 字节）")


def main():
    log.print_and_log("Checking files...")
    log.print_and_log("Checking the executability of system files...")
    check_executable_files('/bin')

    log.print_and_log("Checking temp directory...")
    check_temp_directory('/tmp')


if __name__ == "__main__":
    main()
