import argparse
import sys

import founctions

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='A program to check for system security vulnerabilities.')
    parser.add_argument('--all', action='store_true', help='Run all checks.')
    parser.add_argument('--sysinfo', action='store_true', help='Check system information.')
    parser.add_argument('--alias', action='store_true', help='Check for suspicious aliases.')
    parser.add_argument('--backdoor', action='store_true', help='Check for backdoors.')
    parser.add_argument('--webshell', action='store_true', help='Check for web shells.')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    if args.all:
        print('Running all checks...\n')
        # get_system_info()
        # check_aliases()
        # check_backdoors()
        # check_webshells()
    else:
        if args.sysinfo:
            print('Checking system information...\n')
            # get_system_info()
        if args.alias:
            print('Checking for suspicious aliases...\n')
            # check_aliases()
        if args.backdoor:
            print('Checking for backdoors...\n')
            # check_backdoors()
        if args.webshell:
            print('Checking for web shells...\n')
            # check_webshells()
