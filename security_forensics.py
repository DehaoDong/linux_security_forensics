import argparse
import os
import sys

from modules import check_alias, check_process, check_connections, check_login_log, check_users_history_operations, \
    check_webservers, check_files, check_startups, check_app_packages, check_backdoors, output_result, get_host_info, \
    log, get_users_info, back_up_important_system_files, check_ssh

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
    parser.add_argument('--user', action='store_true', help='备份用户信息(Back up users\' information)')
    parser.add_argument('--systemfile', action='store_true', help='备份重要系统文件(Back up important system files)')
    parser.add_argument('--alias', action='store_true', help='检查Alias(Check aliases)')
    parser.add_argument('--backdoor', action='store_true', help='检查后门(Check for backdoors)')
    parser.add_argument('--ssh', action='store_true', help='检查SSH(Check ssh)')
    parser.add_argument('--process', action='store_true', help='检查进程(Check processes)')
    parser.add_argument('--connection', action='store_true', help='检查网络连接(Check net connections)')
    parser.add_argument('--login', action='store_true', help='检查用户登录日志(Check user login logs)')
    parser.add_argument('--operation', action='store_true', help='检查用户历史操作(Check user history operations)')
    parser.add_argument('--server', action='store_true', help='检查web服务器(Check web servers)')
    parser.add_argument('--file', action='store_true', help='检查异常文件(Check files)')
    parser.add_argument('--startup', action='store_true', help='检查系统启动项(Check startups)')
    parser.add_argument('--package', action='store_true', help='检查应用程序包(Check app packages)')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print("\n*请使用root模式运行(Please run in root mode)\n")
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
            print("")
        if args.user:
            get_users_info.main()
            print()
        if args.systemfile:
            back_up_important_system_files.main()
            print()
        if args.backdoor:
            check_backdoors.main()
            print("")
        if args.ssh:
            check_ssh.main()
            print()
        if args.process:
            check_process.main()
            print("")
        if args.connection:
            check_connections.main()
            print("")
        if args.login: #un
            check_login_log.main()
            print("")
        if args.operation:#un
            check_users_history_operations.main()
            print("")
        if args.server:
            check_webservers.main()
            print("")
        if args.file:#
            check_files.main()
            print("")
        if args.startup:
            check_startups.main()
            print("")
        if args.package:
            check_app_packages.main()
            print("")
