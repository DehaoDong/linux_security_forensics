import subprocess
from modules import log, output_result


def get_installed_packages():
    pkg_managers = [
        ("dpkg-query -W -f='${Package}\n'", "dpkg -s", "dpkg -V"),
        ("rpm -qa", "rpm -qi", "rpm -V"),
        ("pacman -Q", "pacman -Qi", "pacman -Qkk")
    ]

    for list_command, info_command, verify_command in pkg_managers:
        try:
            result = subprocess.run(list_command, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                output = result.stdout
                packages = output.splitlines()
                return packages, info_command, verify_command
        except FileNotFoundError:
            pass

    raise ValueError("No supported package manager found.")


def get_package_info(package, info_command):
    command = f"{info_command} {package}"
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        output = result.stdout

        if output:
            return output
        else:
            return f"No information found for package {package}"
    except Exception as e:
        log.print_and_log(f"Error while retrieving package info for {package}: {e}")
        return None


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
    installed_packages, info_command, verify_command = get_installed_packages()

    log.print_and_log("Backing up details of packages...")
    for package in installed_packages:
        package_info = get_package_info(package, info_command)
        if package_info:
            output_result.write_content("app_packages.txt", package_info)

    verify_packages(installed_packages, verify_command)


if __name__ == "__main__":
    main()
