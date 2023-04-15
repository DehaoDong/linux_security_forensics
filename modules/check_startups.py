import glob
import os
import subprocess
from modules import log, output_result


def get_init_system():
    try:
        output = subprocess.check_output(['ps', '-p', '1', '-o', 'comm='], text=True)
    except subprocess.CalledProcessError:
        log.print_and_log("Error: Unable to determine init system")
        return None

    output = output.strip()
    if output == 'init':
        return 'SysV'
    elif output == 'systemd':
        return 'Systemd'
    elif output == 'upstart':
        return 'Upstart'
    else:
        log.print_and_log(f"Unknown init system: {output}")
        return None


def systemd_services():
    output = subprocess.check_output(['systemctl', 'list-unit-files', '--type=service'], text=True)
    services = []
    for line in output.splitlines():
        if line:
            service_name = line.strip().split()[0]
            services.append(service_name)
    return services


def backup_systemd_logs(services):
    for service in services:
        log.print_and_log(f"Backing up {service}.log")
        journalctl_output = subprocess.check_output(['journalctl', '-u', service], text=True, errors='ignore')
        output_result.write_content(f"init/{service}.log", journalctl_output)


def check_systemd_service_files(services):
    for service in services:
        service_file = f"/etc/systemd/system/{service}.conf"

        log.print_and_log(f"Backing up service file for {service}:")

        output_result.write_content(f"init/{service}.conf", service_file)


def sysv_services():
    init_scripts = glob.glob('/etc/init.d/*')
    services = [os.path.basename(script) for script in init_scripts]
    return services


def backup_sysv_logs(services):
    for service in services:
        log.print_and_log(f"Backing up {service}.log")
        log_path = f"/var/log/{service}.log"
        if os.path.exists(log_path):
            output_result.write_content(f"init/{service}.log", log_path)


def check_sysv_service_files(services):
    for service in services:
        service_file = f"/etc/init.d/{service}.conf"

        log.print_and_log(f"Backing up service file for {service}:")

        output_result.write_content(f"init/{service}.conf", service_file)


def upstart_services():
    conf_files = glob.glob('/etc/init/*.conf')
    services = [os.path.splitext(os.path.basename(conf))[0] for conf in conf_files]
    return services


def backup_upstart_logs(services):
    for service in services:
        log.print_and_log(f"Backing up {service}.log")
        log_path = f"/var/log/upstart/{service}.log"
        if os.path.exists(log_path):
            output_result.write_content(f"init/{service}.log", log_path)


def check_upstart_service_files(services):
    for service in services:
        service_file = f"/etc/init/{service}.conf"

        log.print_and_log(f"Backing up service file for {service}")

        output_result.write_content(f"init/{service}.conf", service_file)


def main():
    log.print_and_log("Checking startups...")
    init_system = get_init_system()
    log.print_and_log(f"Init system: {init_system}")

    if init_system == 'Systemd':
        services = systemd_services()
        backup_systemd_logs(services)
        # check_systemd_service_files(services)
    elif init_system == 'SysV':
        services = sysv_services()
        backup_sysv_logs(services)
        # check_sysv_service_files(services)
    elif init_system == 'Upstart':
        services = upstart_services()
        backup_upstart_logs(services)
        # check_upstart_service_files(services)
    else:
        log.print_and_log("Unsupported init system")


if __name__ == "__main__":
    main()
