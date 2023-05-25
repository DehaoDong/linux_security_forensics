import subprocess
import pwd
from modules import log, output_result


def get_login_records():
    command = "lastlog"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    output = result.stdout
    lines = output.splitlines()[1:]
    login_records = [line.strip() for line in lines if line.strip() and "Never logged in" not in line]
    return login_records


def get_user_details(username):
    user_info = pwd.getpwnam(username)
    return user_info


def get_user_processes(username):
    command = f"ps -u {username}"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    output = result.stdout
    return output


def main():
    log.print_and_log("Storing information of users...")
    login_records = get_login_records()

    users_info = ""
    for record in login_records:
        record_parts = record.split()
        username, tty, login_time = record_parts[0], record_parts[1], " ".join(record_parts[2:])
        log.print_and_log(f"Storing record of {username}...")

        user_info = get_user_details(username)
        user_processes = get_user_processes(username)

        user_info_text = f"""Username: {username}
TTY: {tty}
Login time: {login_time}
User ID: {user_info.pw_uid}
Full name: {user_info.pw_gecos}
Home directory: {user_info.pw_dir}
Shell: {user_info.pw_shell}
Related processes:
{user_processes}
"""

        users_info += user_info_text + "\n"

    output_result.write_content("users_info.txt", users_info.strip())

    if not login_records:
        log.print_and_log("No login records found.")


if __name__ == "__main__":
    main()
