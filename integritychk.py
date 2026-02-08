import hashlib
import os
import time
import requests
from termcolor import colored
import inotify.adapters as watcher

def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest()

def compare_hashes(file_path, md5_hash, sha1_hash, sha256_hash, api_key):
    print(colored("\nComparing Hashes...", "cyan"))

    if not api_key:
        print(colored("Note: VirusTotal API key not provided. Hash comparison may not be perfect.", "yellow"))
        return

    url = f'https://www.virustotal.com/api/v3/files/{md5_hash}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()

        if 'data' in result and 'attributes' in result['data'] and 'last_analysis_stats' in result['data']['attributes']:
            detection_ratio = result['data']['attributes']['last_analysis_stats']['malicious']
            if detection_ratio == 0:
                print(colored("File is safe. No detections found!", "green"))
            else:
                print(colored("Warning: File may be malicious. Detected by some scanners!", "red"))
        else:
            print(colored("Unable to retrieve data from VirusTotal. Please check again later.", "yellow"))
    else:
        print(colored("Error: Unable to connect to VirusTotal. Please check your internet connection.", "yellow"))

def get_stats(file_path):
    stats = os.stat(file_path)
    return (stats.st_size, stats.st_mtime, stats.st_ctime, stats.st_atime, stats.st_gid, stats.st_uid)

def main():
    print(colored("File Integrity Checker", "magenta"))

    file_path = input("Enter the path of the file: ")
    if not os.path.exists(file_path):
        print(colored("Error: File not found!", "red"))
        return

    api_key = input("Enter your VirusTotal API key (leave empty for skipping comparison): ").strip()
    old_hashes, _ = calculate_hashes(file_path)

    watcher.Watch('/path/to/directory', recursive=True)  # replace '/path/to/directory' with the directory you want to monitor

    def on_event(event):
        if event.is_modify:
            new_stats = get_stats(file_path)
            old_size, _, _, _, gid, uid = old_stats
            new_size, _, _, _, _, _ = new_stats

            if old_size != new_size:
                print(colored("File size has changed. Old size:", colored("yellow"), str(old_size)))
                print(colored("New size:", colored("cyan"), str(new_size)))

            md5_hash, sha1_hash, sha256_hash = calculate_hashes(file_path)

            if old_hashes != (md5_hash, sha1_hash, sha256_hash):
                print(colored("\nCalculating Hashes...", "cyan"))
                time.sleep(1)  # Simulate calculation time
                print(colored("New hashes:", colored("cyan"), str((md5_hash, sha1_hash, sha256_hash))))
                compare_hashes(file_path, md5_hash, sha1_hash, sha256_hash, api_key)
            old_hashes = (md5_hash, sha1_hash, sha256_hash)

    watcher.event_listener(on_event)
    watcher.run()

if __name__ == "__main__":
    main()