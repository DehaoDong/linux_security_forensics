import os
import re

# 已知的WebShell特征
webshell_signatures = [
    r'(eval\(|assert\(|base64_decode\(|str_rot13\()',
    r'(\$GLOBALS|\$_SERVER|\$_GET|\$_POST|\$_REQUEST|\$_FILES)',
    r'(passthru\(|shell_exec\(|exec\(|system\(|popen\()'
]

def scan_web_directory_for_webshells(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # 12.2 Web目录遍历
            if file.endswith(('.php', '.aspx', '.jsp', '.pl')):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # 12.3 WebShell文件内容分析
                    for signature in webshell_signatures:
                        if re.search(signature, content, re.IGNORECASE):
                            print(f"Possible WebShell found: {file_path}")
                            break

def main():
    # 您可以根据需要更改要扫描的Web目录
    web_directories_to_scan = ['/var/www/html']

    for directory in web_directories_to_scan:
        print(f"\nScanning web directory '{directory}' for WebShells:")
        scan_web_directory_for_webshells(directory)

if __name__ == "__main__":
    main()
