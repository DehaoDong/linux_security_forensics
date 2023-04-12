import argparse

def run_mode_one():
    print("运行模式一 (Mode One)")

def run_mode_two():
    print("运行模式二 (Mode Two)")

def main():
    parser = argparse.ArgumentParser(description='一个运行在 Linux 上的 Python 项目 (A Python project running on Linux)')

    parser.add_argument('-m', '--mode', type=int, choices=[1, 2], required=True,
                        help='选择程序运行模式 (1 或 2) (Choose the program running mode (1 or 2))')
    parser.add_argument('-l', '--language', type=str, choices=['zh', 'en'], default='zh',
                        help='选择提示信息的语言 (zh 或 en) (Choose the language for prompts (zh or en))')

    args = parser.parse_args()

    if args.language == 'en':
        parser._optionals.title = 'Optional arguments'
        parser._actions[0].help = 'Show this help message and exit'

    if args.mode == 1:
        run_mode_one()
    elif args.mode == 2:
        run_mode_two()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
