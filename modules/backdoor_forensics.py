import os
import glob
import subprocess
import re

from modules import log, output_result


def check_conf(tag, file_path, mode='only'):
    try:
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return ""

        with open(file_path) as f:
            for line in f:
                if len(line) < 3 or line[0] == '#':
                    continue
                if mode == 'only' and f'export {tag}' in line:
                    return line
        return ""
    except:
        return ""


def check_tag(tag, mode='only'):
    suspicious = False
    files = [
        '/root/.bashrc', '/root/.tcshrc', '/root/.bash_profile', '/root/.cshrc', '/root/.tcshrc',
        '/etc/bashrc', '/etc/profile', '/etc/profile.d/', '/etc/csh.login', '/etc/csh.cshrc'
    ]
    home_files = ['/.bashrc', '/.bash_profile', '/.tcshrc', '/.cshrc', '/.tcshrc']

    for dir in os.listdir('/home/'):
        for home_file in home_files:
            file = os.path.join(f'/home/{dir}{home_file}')
            # 备份
            output_result.write_content(f"backdoor/env/{file.replace('/', '_')}", file)
            info = check_conf(tag, file, mode)
            if info:
                suspicious = True

    for file in files:
        if os.path.isdir(file):
            for f in glob.glob(os.path.join(file, '*')):
                # 备份
                output_result.write_content(f"backdoor/env/{f.replace('/', '_')}", f)
                info = check_conf(tag, f, mode)
                if info:
                    suspicious = True
        else:
            # 备份
            output_result.write_content(f"backdoor/env/{file.replace('/', '_')}", file)
            info = check_conf(tag, file, mode)
            if info:
                suspicious = True

    return suspicious


def check_environment_variable_backdoors():
    backdoor_variables = ['LD_PRELOAD', 'LD_AOUT_PRELOAD', 'LD_ELF_PRELOAD', 'LD_LIBRARY_PATH', 'PROMPT_COMMAND']
    found_backdoors = []

    # 备份running env
    for key, value in os.environ.items():
        output_result.write_content("backdoor/env/running_env.txt", f"{key}={value}\n")

    for var in backdoor_variables:
        # 检查运行中的环境变量
        if var in os.environ:
            found_backdoors.append((var, os.environ[var]))
        # 检查配置文件中的环境变量
        if (var not in os.environ or (var, os.environ[var]) not in found_backdoors) and check_tag(var):
            found_backdoors.append(var)

    return found_backdoors


# Check for ld.so.preload backdoor
def check_ld_so_preload_backdoors():
    ld_so_preload_path = '/etc/ld.so.preload'
    sopreload_backdoors = []
    if os.path.exists(ld_so_preload_path):
        with open(ld_so_preload_path) as f:
            content = f.read().strip()
            if content:
                output_result.write_content("backdoor/ld.so.preload", ld_so_preload_path)
                sopreload_backdoors.append(('ld.so.preload', content))
    return sopreload_backdoors


def is_malicious_cron(file_path):
    # 这是一个包含已知恶意字符串的示例列表，您可以根据需要扩展此列表
    malicious_strings = ['rm -rf', 'wget', 'curl', 'nc']

    with open(file_path) as f:
        content = f.read()
        for malicious_string in malicious_strings:
            if malicious_string in content:
                return True
    return False


def check_cron():
    suspicious_files = []
    cron_dirs = [
        '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily',
        '/etc/cron.weekly', '/etc/cron.monthly'
    ]
    for cron_dir in cron_dirs:
        if os.path.isdir(cron_dir):
            for file in glob.glob(os.path.join(cron_dir, '*')):
                output_result.write_content(f"backdoor/cron/{file.replace('/', '_')}", file)
                if is_malicious_cron(file):
                    suspicious_files.append(file)
    return suspicious_files


def check_ssh():
    suspicious_sshd = []
    output = subprocess.check_output(['ps', 'aux'])
    for line in output.splitlines():
        if b'sshd' in line:
            if not b'root' in line and not b'22' in line:
                suspicious_sshd.append(line)
    return suspicious_sshd


def check_ssh_wrapper():
    sshd_path = '/usr/sbin/sshd'
    if os.path.exists(sshd_path) and os.path.isfile(sshd_path):
        output_result.write_content("backdoor/sshd", sshd_path)
        return not os.access(sshd_path, os.X_OK)
    return False


def check_inetd():
    suspicious_inetd = []
    inetd_conf = '/etc/inetd.conf'
    if os.path.exists(inetd_conf):
        output_result.write_content(f"backdoor/{inetd_conf.replace('/', '_')}")
        with open(inetd_conf) as f:
            for line in f:
                if line and line[0] != '#' and re.search(r'\b(?:echo|discard|chargen|daytime|time)\b', line):
                    suspicious_inetd.append(line)
    return suspicious_inetd


def check_xinetd():
    suspicious_xinetd = []
    xinetd_conf_dir = '/etc/xinetd.d'
    if os.path.exists(xinetd_conf_dir) and os.path.isdir(xinetd_conf_dir):
        for file in glob.glob(os.path.join(xinetd_conf_dir, '*')):
            output_result.write_content(f"backdoor/{file.replace('/', '_')}", file)
            with open(file) as f:
                for line in f:
                    if line and line[0] != '#' and 'disable' in line and 'no' in line:
                        suspicious_xinetd.append(file)
                        break
    return suspicious_xinetd


def check_setuid():
    suspicious_setuid_files = []
    output = subprocess.check_output(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'])
    output_result.write_content("backdoor/setuid.txt", output)
    for line in output.splitlines():
        if b'/usr/bin/passwd' not in line and b'/usr/bin/chsh' not in line:
            suspicious_setuid_files.append(line)
    return suspicious_setuid_files


def main():
    log.print_and_log("Checking backdoors...")
    environment_variable_backdoors = check_environment_variable_backdoors()
    if environment_variable_backdoors:
        log.print_and_log("*Found environment variable backdoors:")
        output_result.write_content("suspicious.txt", "Found environment variable backdoors:")
        for backdoor in environment_variable_backdoors:
            log.print_and_log(f"*{backdoor}")
            output_result.write_content("suspicious.txt", f"#{backdoor}")
    else:
        log.print_and_log("No environment variable backdoors found")

    sopreload_backdoors = check_ld_so_preload_backdoors()
    if sopreload_backdoors:
        log.print_and_log("*Found ld.so.preload backdoors:")
        output_result.write_content("suspicious.txt", "Found ld.so.preload backdoors:")
        for backdoor in sopreload_backdoors:
            log.print_and_log(f"*{backdoor}")
            output_result.write_content("suspicious.txt", f"#{backdoor}")
    else:
        log.print_and_log("No ld.so.preload backdoors found")

    cron_backdoors = check_cron()
    if cron_backdoors:
        log.print_and_log("*Found cron backdoors:")
        output_result.write_content("suspicious.txt", "Found cron backdoors:")
        for backdoor in cron_backdoors:
            log.print_and_log(f"*{backdoor}")
            output_result.write_content("suspicious.txt", f"#{backdoor}")
    else:
        log.print_and_log("No cron backdoors found")

    ssh_backdoors = check_ssh()
    if ssh_backdoors:
        log.print_and_log("*Found SSH backdoors:")
        output_result.write_content("suspicious.txt", "Found SSH backdoors:")
        for backdoor in ssh_backdoors:
            log.print_and_log(f"*{backdoor}")
            output_result.write_content("suspicious.txt", f"#{backdoor}")
    else:
        log.print_and_log("No SSH backdoors found")

    sshwrapper_backdoor = check_ssh_wrapper()
    if sshwrapper_backdoor:
        log.print_and_log("*Found SSH wrapper backdoor:")
        output_result.write_content("suspicious.txt", "Found SSH wrapper backdoor:")
        log.print_and_log(f"*{sshwrapper_backdoor}")
        output_result.write_content("suspicious.txt", f"#{sshwrapper_backdoor}")
    else:
        log.print_and_log("No SSH wrapper backdoor found")

    inetd_backdoors = check_inetd()
    if inetd_backdoors:
        log.print_and_log("*Found inetd backdoors:")
        output_result.write_content("suspicious.txt", "Found inetd backdoors:")
        for backdoor in inetd_backdoors:
            log.print_and_log(f"*{backdoor}")
            output_result.write_content("suspicious.txt", f"#{backdoor}")
    else:
        log.print_and_log("No inetd backdoors found")


if __name__ == "__main__":
    main()
