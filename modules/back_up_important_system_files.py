import os
from modules import log, output_result


def main():
    log.print_and_log("Backing up important system files...")

    files_to_backup = []
    with open('./data/important_sys_files', 'r') as f:
        for line in f:
            files_to_backup.append(line.strip())

    for file in files_to_backup:
        if os.path.exists(file):
            output_result.write_content("system_files/" + file.replace('/', '_'), file)
            log.print_and_log(f"Backed up file {file}.")
        else:
            log.print_and_log(f"File {file} not found. Skipping backup.")


if __name__ == "__main__":
    main()
