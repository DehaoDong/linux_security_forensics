import os
import subprocess

from modules import output_result, log


def get_users():
    with open('/etc/passwd', 'r') as f:
        users = [line.split(':')[0] for line in f]
    return users


def check_alias(user):
    suspicious_aliases = []

    for config_file in ['.bashrc', '.bash_profile']:
        try:
            command = f'sudo -u {user} bash -i -c "source ~/{config_file} && alias"'
            aliases_output = subprocess.check_output(command, shell=True, text=True, stderr=subprocess.DEVNULL)
            aliases = aliases_output.strip().split('\n')

            # 遍历所有 alias，筛选出可能被视为可疑的别名
            for alias in aliases:
                output_result.write_content(f'aliases/{user}_aliases.txt', alias)
                alias_name, alias_command = alias.split("=", 1)

                # 确保 alias 命令具有正确的引号
                if not alias_command.startswith("'") or not alias_command.endswith("'"):
                    suspicious_aliases.append(alias_name)
                    continue

                # 去掉引号
                alias_command = alias_command[1:-1]

                # 查找修改后的系统命令
                if alias_command.startswith('/') or alias_command.startswith('./'):
                    suspicious_aliases.append(alias_name)

                # 查找环境变量攻击
                elif "export " in alias_command:
                    suspicious_aliases.append(alias_name)

                # 查找输出重定向攻击
                elif ">" in alias_command:
                    suspicious_aliases.append(alias_name)

        except subprocess.CalledProcessError:
            pass

    return suspicious_aliases


def main():
    users = get_users()
    for user in users:
        log.print_and_log(f"Checking aliases for user {user}...")
        suspicious_aliases = check_alias(user)
        if suspicious_aliases:
            output_result.write_content(f"suspicious.txt", "Suspicious aliases found:")
            log.print_and_log(f"*Suspicious aliases found for user {user}:")
            for alias in suspicious_aliases:
                log.print_and_log(f"*{alias}")
                output_result.write_content(f"suspicious.txt", f"{user}: {alias}")
        else:
            log.print_and_log(f"No suspicious aliases found for user {user}.")


if __name__ == "__main__":
    main()
