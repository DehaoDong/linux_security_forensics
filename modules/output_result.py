import datetime
import os
import shutil


def create_result_directory(base_path, hostname):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    directory_name = f"{timestamp}_{hostname}"
    results_dir = os.path.join(base_path, directory_name)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir


def compress_results(results_dir, compressed_file):
    shutil.make_archive(compressed_file, "gztar", results_dir)