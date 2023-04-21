import subprocess
from modules import log, output_result


# 获取可用的包管理器以及已安装的软件包
def get_installed_packages():
    pkg_managers = [
        ("dpkg-query -W -f='${Package}\n'", "dpkg -V"),
        ("rpm -qa", "rpm -V"),
        ("pacman -Q", "pacman -Qkk")
    ]

    for list_command, verify_command in pkg_managers:
        try:
            result = subprocess.run(list_command, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                output = result.stdout
                packages = output.splitlines()
                return packages, verify_command
        except FileNotFoundError:
            pass

    raise ValueError("No supported package manager found.")


def verify_packages(packages, verify_command):
    for package in packages:
        log.print_and_log(f"Checking package of {package}...")
        command = f"{verify_command} {package}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout

        if output:
            log.print_and_log(f"*Package verification results for {package}:")
            log.print_and_log(f"*{output}")

            output_result.write_content("suspicious.txt", f"Package verification results for {package}:")
            output_result.write_content("suspicious.txt", output)


def main():
    log.print_and_log("Checking app packages...")
    installed_packages, verify_command = get_installed_packages()
    packages_string = "\n".join(installed_packages)
    output_result.write_content("app_packages.txt", packages_string)
    verify_packages(installed_packages, verify_command)


if __name__ == "__main__":
    main()
