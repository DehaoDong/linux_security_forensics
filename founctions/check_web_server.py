import os
import re
import glob

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

            if file.endswith(('.php', '.aspx', '.jsp', '.pl')):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    for signature in webshell_signatures:
                        if re.search(signature, content, re.IGNORECASE):
                            print(f"Possible WebShell found: {file_path}")
                            break

# 提取web服务器的web目录
web_server_directories = {
    'nginx': '/usr/local/nginx/html',
    'tomcat': '/usr/local/tomcat/webapps',
    'jetty': '/opt/jetty/webapps',
    'apache': '/var/www/html',
    'resin': '/usr/local/resin/webapps',
    'jboss': '/usr/local/jboss/server/default/deploy',
    'weblogic': '/usr/local/weblogic/user_projects/domains/*/autodeploy',
    'lighttpd': '/var/www'
}


def main():
    for server_name, web_directory in web_server_directories.items():
        if '*' in web_directory:
            for directory in glob.glob(web_directory.replace('*', '*')):
                print(f"\nScanning {server_name} web directory '{directory}' for WebShells:")
                scan_web_directory_for_webshells(directory)
        elif os.path.exists(web_directory):
            print(f"\nScanning {server_name} web directory '{web_directory}' for WebShells:")
            scan_web_directory_for_webshells(web_directory)
        else:
            print(f"\n{server_name} web directory '{web_directory}' not found.")


if __name__ == "__main__":
    main()