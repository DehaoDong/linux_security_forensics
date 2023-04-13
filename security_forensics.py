import argparse
import os
import sys

from modules import check_alias, check_process, check_connections, check_login_log, check_users_history_operations, \
    check_webshells, check_files, check_startups, check_app_packages, check_backdoors, output_result, get_host_info, log


if __name__ == "__main__":
    # running options
    parser = argparse.ArgumentParser(description='LINUX SECURITY FORENSICS\n', add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='显示帮助信息并退出(Show help message and exit)'
    )
    parser.add_argument('-d', '--destination', action='store',
                        default='./results/',
                        dest='output_dir',
                        help='指定取证结果存储目录(Specify directory for storing forensics result) <default is \'./results\'>'
                        )
    parser.add_argument('-a', '--all', action='store_true', help='运行所有检查(Run all checks)')
    parser.add_argument('--alias', action='store_true', help='检查Alias(Check aliases)')
    parser.add_argument('--backdoor', action='store_true', help='检查后门(Check for backdoors)')
    parser.add_argument('--process', action='store_true', help='检查进程(Check processes)')
    parser.add_argument('--connection', action='store_true', help='检查网络连接(Check net connections)')
    parser.add_argument('--login', action='store_true', help='检查用户登录日志(Check user login logs)')
    parser.add_argument('--operation', action='store_true', help='检查用户历史操作(Check user history operations)')
    parser.add_argument('--webshell', action='store_true', help='检查webshell(Check for webshells)')
    parser.add_argument('--file', action='store_true', help='检查异常文件(Check files)')
    parser.add_argument('--startup', action='store_true', help='检查系统启动项(Check startups)')
    parser.add_argument('--package', action='store_true', help='检查应用程序包(Check app packages)')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    # get host information
    host_info = get_host_info.get_host_info()

    # creat new log
    log_path = log.creat_new_log()
    os.environ['log_path'] = log_path

    # creat new result
    result_dir = output_result.create_result_directory(args.output_dir, host_info['Node Name']) + '/'
    os.environ['result_dir'] = result_dir
    log.print_and_log(f"取证结果存放目录(directory for storing forensics result)：{result_dir}\n")

    # print host information
    log.print_and_log("系统信息(System information):")
    output_result.write_content("host_info.txt", "系统信息(System information):")
    for key, value in host_info.items():
        log.print_and_log(f"{key}: {value}")
        output_result.write_content("host_info.txt", f"{key}: {value}")
    print("")

    if args.all:
        log.print_and_log('执行所有检查(Running all checks)...\n')
    else:
        if args.alias:
            check_alias.main()
        if args.backdoor:
            check_backdoors.main()
        if args.process:
            check_process.main()
        if args.connection:
            check_connections.main()
        if args.login:
            check_login_log.main()
        if args.operation:
            check_users_history_operations.main()
        if args.webshell:
            check_webshells.main()
        if args.file:
            check_files.main()
        if args.startup:
            check_startups.main()
        if args.package:
            check_app_packages.main()
