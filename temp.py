import os
import socket
import datetime
import shutil
from pathlib import Path

def traverse_bin_dirs(bin_dirs):
    files = []
    for bin_dir in bin_dirs:
        if os.path.exists(bin_dir):
            for item in os.listdir(bin_dir):
                file_path = os.path.join(bin_dir, item)
                if os.path.isfile(file_path):
                    files.append(file_path)
    return files

def create_results_directory(base_path, hostname):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    directory_name = f"{timestamp}_{hostname}"
    results_dir = os.path.join(base_path, directory_name)
    os.makedirs(results_dir, exist_ok=True)
    return results_dir

def save_file_contents(src_file, dest_file):
    try:
        with open(src_file, "rb") as src, open(dest_file, "wb") as dest:
            shutil.copyfileobj(src, dest)
    except Exception as e:
        print(f"Error copying file {src_file}: {e}")

def save_results(files, results_dir):
    for file in files:
        file_name = os.path.basename(file)
        dest_file = os.path.join(results_dir, file_name)
        save_file_contents(file, dest_file)

def compress_results(results_dir, compressed_file):
    shutil.make_archive(compressed_file, "gztar", results_dir)

if __name__ == "__main__":
    bin_dirs = ["/bin"]
    base_results_path = "./results"

    hostname = socket.gethostname()
    files = traverse_bin_dirs(bin_dirs)
    results_dir = create_results_directory(base_results_path, hostname)
    save_results(files, results_dir)

    compressed_file = os.path.join(base_results_path, f"{os.path.basename(results_dir)}")
    compress_results(results_dir, compressed_file)

    print(f"Results saved in: {results_dir}")
    print(f"Compressed results saved as: {compressed_file}.tar.gz")
