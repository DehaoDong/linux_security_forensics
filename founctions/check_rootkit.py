import os

# 已知的rootkit和恶意软件文件名
known_malware_names = [
    'rootkit_example',
    'malware_example'
]

# 恶意文件扩展名
malicious_extensions = [
    '.vbs',
    '.bat',
    '.sh'
]


def scan_directory_for_malware(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_name, file_extension = os.path.splitext(file)

            if file_name in known_malware_names:
                print(f"Possible malware found: {file_path}")

            if file_extension in malicious_extensions:
                print(f"File with malicious extension found: {file_path}")


def main():
    # 您可以根据需要更改要扫描的目录
    directories_to_scan = ['/tmp', '/usr/local']

    for directory in directories_to_scan:
        print(f"\nScanning directory '{directory}' for malware:")
        scan_directory_for_malware(directory)


if __name__ == "__main__":
    main()
