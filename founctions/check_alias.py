#  系统初始化alias检查
import subprocess


def check_alias():
    try:
        aliases = subprocess.check_output("alias", shell=True, text=True)
        suspicious_aliases = []

        # 遍历所有 alias，筛选出可能被视为可疑的别名
        for alias in aliases:
            alias_name, alias_command = alias.split("=")
            if "rm -i" in alias_command:
                suspicious_aliases.append(alias_name)
            elif "cp -i" in alias_command:
                suspicious_aliases.append(alias_name)
            elif "mv -i" in alias_command:
                suspicious_aliases.append(alias_name)
            elif "--color=auto" in alias_command:
                if "ls " in alias_command:
                    suspicious_aliases.append(alias_name)
                elif "grep " in alias_command:
                    suspicious_aliases.append(alias_name)
            elif "ps auxf" in alias_command:
                suspicious_aliases.append(alias_name)

        return suspicious_aliases
    except subprocess.CalledProcessError:
        return []


def main():
    print("\nChecking aliases...")
    suspicious_aliases = check_alias()
    if suspicious_aliases:
        print("Suspicious aliases found:")
        for alias in suspicious_aliases:
            print(alias)
    else:
        print("No suspicious aliases found.")


if __name__ == "__main__":
    main()
