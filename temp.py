import requests

def download_malicious_ip_database(url, file_path):
    response = requests.get(url)

    if response.status_code == 200:
        with open(file_path, "wb") as f:
            f.write(response.content)
    else:
        print(f"Failed to download database. Status code: {response.status_code}")

if __name__ == "__main__":
    url = "https://reputation.alienvault.com/reputation.generic"
    file_path = "data/ip_reputation_generic.txt"

    download_malicious_ip_database(url, file_path)
    print(f"Downloaded database to {file_path}")
