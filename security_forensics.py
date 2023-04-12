import argparse
import sys
from modules import check_alias, check_process, check_connections, check_login_log, check_users_history_operations, \
    check_webshells, check_files, check_startups, check_app_packages, check_backdoors

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LINUX SECURITY FORENSICS', add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='显示帮助信息并退出   Show help message and exit'
    )
    parser.add_argument('-d', '--destination', action='store',
                        default='./results/',
                        dest='output_dir',
                        help='指定取证结果存储目录（默认为\'./results\'）   '
                             + 'Specify the directory for storing forensics result(default is \'./result\').'
                        )
    parser.add_argument('-a', '--all', action='store_true', help='运行所有检查   Run all checks.')
    parser.add_argument('--alias', action='store_true', help='检查Alias   Check aliases.')
    parser.add_argument('--backdoor', action='store_true', help='检查后门   Check for backdoors.')
    parser.add_argument('--process', action='store_true', help='检查进程   Check processes.')
    parser.add_argument('--connection', action='store_true', help='检查网络连接   Check net connections.')
    parser.add_argument('--login', action='store_true', help='检查用户登录日志   Check user login logs.')
    parser.add_argument('--operation', action='store_true', help='检查用户历史操作   Check user history operations.')
    parser.add_argument('--webshell', action='store_true', help='检查webshell   Check for webshells.')
    parser.add_argument('--file', action='store_true', help='检查异常文件   Check files.')
    parser.add_argument('--startup', action='store_true', help='检查系统启动项   Check startups.')
    parser.add_argument('--package', action='store_true', help='检查应用程序包   Check app packages.')

    args = parser.parse_args()

    output_dir = args.output_dir
    print(f"输出目录(output directory)：{output_dir}")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    if args.all:
        print('Running all checks...\n')
    else:
        if args.alias:
            print("\nChecking aliases...\n")
            check_alias.main()
        if args.backdoor:
            print('Checking for backdoors...\n')
            check_backdoors.main()
        if args.process:
            print('Checking processes...\n')
            check_process.main()
        if args.connection:
            print('Checking net connections...\n')
            check_connections.main()
        if args.login:
            print('Checking user login logs...\n')
            check_login_log.main()
        if args.operation:
            print('Checking user history operations...\n')
            check_users_history_operations.main()
        if args.webshell:
            print('Checking for webshells...\n')
            check_webshells.main()
        if args.file:
            print('Checking files...\n')
            check_files.main()
        if args.startup:
            print('Checking startups...\n')
            check_startups.main()
        if args.package:
            print('Checking app packages...\n')
            check_app_packages.main()
