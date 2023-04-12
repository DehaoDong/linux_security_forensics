import logging
import os
import time


def print_and_log(message):
    print(message)
    logging.basicConfig(filename='../log/log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

    # print and log the input string
    logging.info(message)


def creat_new_log():
    # 获取当前时间并格式化
    current_time = time.strftime("%Y-%m-%d_%H-%M", time.localtime())

    # 创建日志文件
    log_filename = f"{current_time}_log.txt"
    log_file_path = os.path.join('./log', log_filename)
    open(log_file_path, "w")
    return log_file_path
