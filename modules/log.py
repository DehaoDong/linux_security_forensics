import logging
import os
import time


def print_and_log(message):
    log_path = os.environ.get('log_path')

    print(message)

    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s\n%(message)s')
    logging.info(message)


def creat_new_log():
    # 获取当前时间并格式化
    current_time = time.strftime("%Y-%m-%d_%H-%M", time.localtime())

    # 创建日志文件
    log_filename = f"{current_time}_log.txt"
    log_file_path = os.path.join('./log', log_filename)
    open(log_file_path, "wb")
    return log_file_path
