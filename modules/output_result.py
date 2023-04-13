import datetime
import os
import shutil


def create_result_directory(base_path, hostname):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    directory_name = f"{timestamp}_{hostname}"
    results_dir = os.path.join(base_path, directory_name)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir


def write_content(file_path, content):
    result_dir = os.environ.get('result_dir')

    file_path = result_dir + file_path

    # 创建文件所在目录
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    # 打开文件，如果文件不存在则创建
    with open(file_path, "a") as f:
        # 检查content是否为文件路径，如果是，则读取文件内容并写入
        if os.path.isfile(content):
            with open(content, "r") as content_file:
                f.write(content_file.read())
        # 如果content不是文件路径，直接将其内容写入
        else:
            f.write(content+'\n')


def compress_results(results_dir, compressed_file):
    shutil.make_archive(compressed_file, "gztar", results_dir)