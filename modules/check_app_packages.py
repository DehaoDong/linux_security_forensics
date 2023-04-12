import subprocess


def get_installed_packages():
    command = "dpkg-query -W -f='${Package}\n'"
    result = subprocess.run(command, capture_output=True, text=True, shell=True)
    output = result.stdout
    packages = output.splitlines()
    return packages


def verify_packages(packages):
    for package in packages:
        command = f"dpkg -V {package}"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout

        if output:
            print(f"Package verification results for {package}:")
            print(output)
        else:
            print(f"No issues found in {package}.")


if __name__ == "__main__":
    installed_packages = get_installed_packages()
    verify_packages(installed_packages)
