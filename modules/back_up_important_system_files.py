from modules import log, output_result


def main():
    log.print_and_log("Backing up important system files...")

    files_to_backup = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/kern.log",
        "/var/log/faillog",
        "/var/log/lastlog",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/dmesg",
        "/var/log/apt/history.log",
        "/var/log/yum.log",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/var/log/sudo",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/var/spool/cron/crontabs",
        "/root/.bash_history",
        "/home/username/.bash_history",
        "/etc/hosts",
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/etc/iptables",
        "/etc/sysconfig/iptables",
        "/etc/fstab"
    ]

    for file in files_to_backup:
        output_result.write_content("system_files/"+file.replace('/', '_'), file)

    log.print_and_log("Backup completed")


if __name__ == "__main__":
    main()
