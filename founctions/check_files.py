import os
import hashlib


# 系统重要文件完整性扫描
def check_system_files_integrity(important_files):
    expected_hashes = {}
    with open("../database/file_hash", 'r') as f:
        for line in f:
            file, hash_value = line.strip().split(': ')
            expected_hashes[file] = hash_value

    for file in important_files:
        file_hash = get_file_hash(file)
        # 如果hash不符合预期
        if file_hash != expected_hashes[file]:
            print(f"{file} has been modified!")


# 获取文件的哈希值
def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()
            return file_hash
    except FileNotFoundError:
        return "File not found"


# 系统文件可执行性扫描
def check_executable_files(path):
    for root, _, files in os.walk(path):
        for file in files:
            if not os.access(os.path.join(root, file), os.X_OK):
                print(f"non-executable: {os.path.join(root, file)}")


# 临时目录文件安全扫描
def check_temp_directory(path):
    # 检查具有可执行性的临时文件
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.X_OK):
                print(f"临时文件 {file_path} 可被执行！")

    # 检查大文件
    max_size = 10 * 1024 * 1024  # 10MB
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                print(f"临时文件 {file_path} 过大！（超过 {max_size} 字节）")


# 用户目录文件扫描
def check_user_directories(path):
    # 查找具有全局可写权限的文件
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if os.access(file_path, os.W_OK) and not os.path.islink(file_path):
                 print(f"用户文件 {file_path} 具有全局可写权限")

    # 查找隐藏文件
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.startswith("."):
                file_path = os.path.join(root, file)
                print(f"用户文件 {file_path} 为隐藏文件")


# 可疑隐藏文件扫描
def check_hidden_files(path):
    for root, _, files in os.walk(path):
        for file in files:
            if file.startswith('.'):
                print(f"Hidden file: {os.path.join(root, file)}")


def main():
    important_files = ['/etc/passwd', '/etc/shadow']
    print("\nChecking system files integrity...")
    check_system_files_integrity(important_files)

    print("\nChecking files executability...")
    check_executable_files('/bin')

    print("\nChecking temp directory...")
    check_temp_directory('/tmp')

    # print("\nChecking user directories...")
    # user_dir = "/home"
    # user_directories = [os.path.join(user_dir, d) for d in os.listdir(user_dir) if
    #                     os.path.isdir(os.path.join(user_dir, d))]
    # for user_directory in user_directories:
    #     print(f"\n用户目录：{user_directory}")
    #     check_user_directories(user_directory)

    print("\nChecking hidden files...")
    check_hidden_files('/home')


if __name__ == "__main__":
    main()
