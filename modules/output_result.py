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
    with open(file_path, "ab") as f:
        if isinstance(content, list):
            content = '\n'.join(content)
        # 检查content是否为文件路径，如果是，则读取文件内容并写入
        if os.path.isfile(content):
            with open(content, "rb") as content_file:
                f.write(content_file.read())
        # 如果content不是文件路径，直接将其内容写入
        else:
            f.write((content+'\n').encode())


def compress_results():
    result_dir = os.environ.get('result_dir')

    # 删除result_dir末尾的'/'
    result_dir = result_dir.rstrip('/')

    # 获取结果目录名
    result_dir_name = os.path.basename(result_dir)

    # 获取结果目录的上级目录路径
    parent_dir = os.path.dirname(result_dir)

    # 压缩结果目录
    compressed_file = os.path.join(parent_dir, f"{result_dir_name}.tar.gz")
    shutil.make_archive(os.path.join(parent_dir, result_dir_name), "gztar", parent_dir, result_dir_name)



