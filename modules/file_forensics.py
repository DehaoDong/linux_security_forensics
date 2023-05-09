import os
import stat
import datetime
import pwd
import grp
from modules import log, output_result


# 备份文件详情
def backup_file_details(path, output_file):
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_stat = os.stat(file_path)

                file_type = "unknown"
                if stat.S_ISREG(file_stat.st_mode):
                    file_type = "regular file"
                elif stat.S_ISDIR(file_stat.st_mode):
                    file_type = "directory"
                elif stat.S_ISLNK(file_stat.st_mode):
                    file_type = "symbolic link"

                file_mode = stat.filemode(file_stat.st_mode)
                file_owner = pwd.getpwuid(file_stat.st_uid).pw_name
                file_group = grp.getgrgid(file_stat.st_gid).gr_name
                file_size = file_stat.st_size
                file_blocks = file_stat.st_blocks
                file_block_size = file_stat.st_blksize
                file_links = file_stat.st_nlink
                file_inode = file_stat.st_ino
                file_ctime = datetime.datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                file_mtime = datetime.datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                file_atime = datetime.datetime.fromtimestamp(file_stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')

                symlink_target = ""
                if file_type == "symbolic link":
                    symlink_target = os.readlink(file_path)

                file_details = f"{file_path}\nType: {file_type}\nMode: {file_mode}\nOwner: {file_owner}\nGroup: {file_group}\nSize: {file_size}\nBlocks: {file_blocks}\nBlock Size: {file_block_size}\nLinks: {file_links}\nInode: {file_inode}\nCreation Time: {file_ctime}\nModification Time: {file_mtime}\nAccess Time: {file_atime}\nSymlink Target: {symlink_target}\n"
                output_result.write_content(output_file, file_details)

            except PermissionError:
                log.print_and_log(f"Permission denied for {file_path}")
                output_result.write_content("suspicious.txt", f"Permission denied for {file_path}")


# 系统文件可执行性扫描
def check_executable_files(path):
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            log.print_and_log(f"Checking {file_path}...")
            if not os.access(file_path, os.X_OK):
                output_result.write_content("suspicious.txt", f"non-executable: {os.path.join(root, file)}")
                log.print_and_log(f"*non-executable: {os.path.join(root, file)}")


# 临时目录文件安全扫描
def check_temp_directory(path):
    # 检查具有可执行性的临时文件
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            log.print_and_log(f"Checking {file_path}...")
            try:
                if os.access(file_path, os.X_OK):
                    output_result.write_content("suspicious.txt", f"Temporary file {file_path} is executable")
                    log.print_and_log(f"*Temporary file {file_path} is executable")
            except PermissionError:
                log.print_and_log(f"Permission denied for {file_path}")
                output_result.write_content("suspicious.txt", f"Permission denied for {file_path}")

    # 检查大文件
    max_size = 10 * 1024 * 1024  # 10MB
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size = os.path.getsize(file_path)
                if file_size > max_size:
                    output_result.write_content("suspicious.txt", f"Temporary file {file_path} is too big！(more than {max_size} bytes)")
                    log.print_and_log(f"*Temporary file {file_path} is too big！(more than {max_size} bytes)")
            except PermissionError:
                log.print_and_log(f"Permission denied for {file_path}")
                output_result.write_content("suspicious.txt", f"Permission denied for {file_path}")


def main():
    log.print_and_log("Checking files...")
    log.print_and_log("Backing up bin file details...")
    backup_file_details('/bin', 'file/bin.txt')

    log.print_and_log("Backing up tmp file details...")
    backup_file_details('/tmp', 'file/tmp.txt')

    log.print_and_log("Checking the executability of system files...")
    check_executable_files('/bin')

    log.print_and_log("Checking temp directory...")
    check_temp_directory('/tmp')


if __name__ == "__main__":
    main()
