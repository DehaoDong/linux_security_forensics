import subprocess
import os

from modules import output_result, log


def check_alias():
    try:
        command = 'bash -i -c "source ~/.bashrc && alias"'
        aliases_output = subprocess.check_output(command, shell=True, text=True)
        aliases = aliases_output.strip().split('\n')
        suspicious_aliases = []

        # 遍历所有 alias，筛选出可能被视为可疑的别名
        for alias in aliases:
            # print(alias)
            output_result.write_content('aliases.txt', alias)
            alias_name, alias_command = alias.split("=", 1)

            # 确保 alias 命令具有正确的引号
            if not alias_command.startswith("'") or not alias_command.endswith("'"):
                suspicious_aliases.append(alias_name)
                continue

            # 去掉引号
            alias_command = alias_command[1:-1]

            # 查找修改后的系统命令
            if alias_command != os.path.basename(alias_command):
                suspicious_aliases.append(alias_name)

            # 查找环境变量攻击
            elif "export " in alias_command:
                suspicious_aliases.append(alias_name)

            # 查找输出重定向攻击
            elif ">" in alias_command:
                suspicious_aliases.append(alias_name)

        return suspicious_aliases
    except subprocess.CalledProcessError:
        return []


def main():
    log.print_and_log("Checking aliases...")
    suspicious_aliases = check_alias()
    if suspicious_aliases:
        log.print_and_log("Suspicious aliases found:")
        for alias in suspicious_aliases:
            log.print_and_log(alias)
    else:
        log.print_and_log("No suspicious aliases found.")


if __name__ == "__main__":
    main()
