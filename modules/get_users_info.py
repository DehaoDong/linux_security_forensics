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
    log.print_and_log("Storing users' information...")
    login_records = get_login_records()

    for record in login_records:
        record_parts = record.split()
        username, tty, login_time = record_parts[0], record_parts[1], " ".join(record_parts[2:])

        output_result.write_content("users_info.txt", f"Username: {username}")
        output_result.write_content("users_info.txt", f"TTY: {tty}")
        output_result.write_content("users_info.txt", f"Login time: {login_time}")

        user_info = get_user_details(username)
        output_result.write_content("users_info.txt", f"User ID: {user_info.pw_uid}")
        output_result.write_content("users_info.txt", f"Full name: {user_info.pw_gecos}")
        output_result.write_content("users_info.txt", f"Home directory: {user_info.pw_dir}")
        output_result.write_content("users_info.txt", f"Shell: {user_info.pw_shell}")

        output_result.write_content("users_info.txt", "Related processes:")
        user_processes = get_user_processes(username)
        output_result.write_content("users_info.txt", user_processes)

        output_result.write_content("users_info.txt", '')

    if not login_records:
        print("No login records found.")


if __name__ == "__main__":
    main()
