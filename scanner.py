import os
import hashlib
import mmap
import tkinter as tk
from tkinter import ttk
from tqdm import tqdm

def get_num_lines(file_path):
    fp = open(file_path, "r+")
    buf = mmap.mmap(fp.fileno(), 0)
    lines = 0
    while buf.readline():
        lines += 1
    return lines

def load_malware_hashes(file_path):
    with open(file_path, 'r') as f:
        malware_hashes = [line.strip() for line in tqdm(f, total=get_num_lines(file_path), desc='Loading malware hashes')]
    return set(malware_hashes)

def check_files_for_malware(malware_hashes, root_dir, progress_bar, file_label):
    infected_files = []
    total_files = sum(len(files) for _, _, files in os.walk(root_dir))
    progress_bar.config(maximum=total_files)
    file_count = 0
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_label.config(text=file_path)
            try:
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read()).hexdigest()
                    if file_hash in malware_hashes:
                        infected_files.append(file_path)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
            file_count += 1
            progress_bar.config(value=file_count)
            progress_bar.update()
    return infected_files

def scan_directory():
    root_dir = entry.get()
    progress_bar.config(mode='indeterminate')
    progress_bar.start()
    malware_hashes_file = 'VirusHashes.txt'
    malware_hashes = load_malware_hashes(malware_hashes_file)
    infected_files = check_files_for_malware(malware_hashes, root_dir, progress_bar, file_label)
    progress_bar.stop()
    progress_bar.config(mode='determinate')
    if infected_files:
        result_label.config(text="Infected files found:\n")
        for file in infected_files:
            result_label.config(text=f"{result_label.cget('text')}{file}\n")
    else:
        result_label.config(text="No infected files found.")

root = tk.Tk()
root.title("Malware Scanner")

label = tk.Label(root, text="Enter the root directory to scan:")
label.pack()

entry = tk.Entry(root, width=50)
entry.pack()

button = tk.Button(root, text="Scan", command=scan_directory)
button.pack()

progress_bar = ttk.Progressbar(root, orient='horizontal', length=200, mode='determinate')
progress_bar.pack()

file_label = tk.Label(root, text="")
file_label.pack()

result_label = tk.Label(root, text="")
result_label.pack()

root.mainloop()
