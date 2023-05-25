import argparse
import os
import sys

from modules import alias_forensics, process_forensics, connection_forensics, login_forensics, operation_forensics, \
    webserver_forensics, file_forensics, startup_forensics, app_package_forensics, backdoor_forensics, output_result, get_host_info, \
    log, users_info_forensics, backup_sys_file, ssh_forensics, disable_network

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
    parser.add_argument('-i', '--isolate', action='store_true', help='断开所有网络连接隔离本机(Disable all network '
                                                                     'connections to isolate this machine)')
    parser.add_argument('-a', '--all', action='store_true', help='运行所有检查(Run all checks)')
    parser.add_argument('--user', action='store_true', help='备份用户信息(Back up users\' information)')
    parser.add_argument('--sysfile', action='store_true', help='备份重要系统文件(Back up important system files)')
    parser.add_argument('--alias', action='store_true', help='检查Alias(Check aliases)')
    parser.add_argument('--backdoor', action='store_true', help='检查后门(Check for backdoors)')
    parser.add_argument('--ssh', action='store_true', help='检查SSH(Check ssh)')
    parser.add_argument('--proc', action='store_true', help='检查进程(Check processes)')
    parser.add_argument('--conn', action='store_true', help='检查网络连接(Check net connections)')
    parser.add_argument('--login', action='store_true', help='检查用户登录日志(Check user login logs)')
    parser.add_argument('--oper', action='store_true', help='检查用户历史操作(Check user history operations)')
    parser.add_argument('--server', action='store_true', help='检查web服务器(Check web servers)')
    parser.add_argument('--file', action='store_true', help='检查异常文件(Check files)')
    parser.add_argument('--startup', action='store_true', help='检查系统启动项(Check startups)')
    parser.add_argument('--pkg', action='store_true', help='检查应用程序包(Check app packages)')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print("\n*请使用root模式运行(Please run in root mode)\n")
        print("*请使用'./python security_forensics.py'来避免被系统劫持影响(Please use '. /python security_forensics.py' "
              "to avoid being affected by system hijacking)\n")
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
    print()

    # 断网隔离
    if args.isolate:
        disable_network.main()

    if args.all:
        log.print_and_log('执行所有检查(Running all checks)...\n')
        users_info_forensics.main()
        print()
        backup_sys_file.main()
        print()
        alias_forensics.main()
        print()
        backdoor_forensics.main()
        print()
        ssh_forensics.main()
        print()
        login_forensics.main()
        print()
        connection_forensics.main()
        print()
        process_forensics.main()
        print()
        startup_forensics.main()
        print()
        operation_forensics.main()
        print()
        webserver_forensics.main()
        print()
        file_forensics.main()
        print()
        app_package_forensics.main()
        print()
    else:
        if args.alias:
            alias_forensics.main()
            print()
        if args.user:
            users_info_forensics.main()
            print()
        if args.sysfile:
            backup_sys_file.main()
            print()
        if args.backdoor:
            backdoor_forensics.main()
            print()
        if args.ssh:
            ssh_forensics.main()
            print()
        if args.proc:
            process_forensics.main()
            print()
        if args.conn:
            connection_forensics.main()
            print()
        if args.login:
            login_forensics.main()
            print()
        if args.oper:
            operation_forensics.main()
            print()
        if args.server:
            webserver_forensics.main()
            print()
        if args.file:
            file_forensics.main()
            print()
        if args.startup:
            startup_forensics.main()
            print()
        if args.pkg:
            app_package_forensics.main()
            print()

    output_result.compress_results()
