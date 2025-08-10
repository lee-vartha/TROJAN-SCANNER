import subprocess # lets me run external programs
import os # to interact with the operating system
import hashlib # to have an interface to hash files
import requests # to interact with web services/make HTTP requests
import threading # to use concurrency for running tasks
import time # getting current date and time
import tkinter as tk # for the GUI
from tkinter import filedialog, scrolledtext, ttk
from datetime import datetime

YARA_PATH = "yara64.exe"
RULES_FILE = "rules\\trojan_rules.yar"
VT_API_KEY = "34923601df873108e50af7f497e636c88f6087851ca5321dde99cfebec76f509"
VT_URL = "https://virustotal.com/api/v3/files/"
UPLOAD_URL = "https://www.virustotal.com/api/v3"
DELAY = 15 # api rate limit is 1 req per 15 sec

# -------- GUI --------
root = tk.Tk() # main window
root.title("TREDR - Trojan Risk Education & Detection Resource") # main title seen in the window 
root.geometry("760x500") # size of the entire screen

title_label = tk.Label(root, text="YARA analysis + VirusTotal hybrid verification", 
                       font=("Helvetica", 18, "bold"), bg="#f0f2f5", fg="#1a1a1a")
title_label.pack(pady=10)

desc_label = tk.Label(root, text="Choose a folder to scan for suspicious files using YARA + VirusTotal", font=("Helvetica", 10), bg="#f0f2f5")
desc_label.pack(pady=5)

frame = tk.Frame(root)
frame.pack(pady=10)

def browse_and_scan():
    folder = filedialog.askdirectory()
    if folder:
        scan_folder(folder) # not applicable until backend logic is set
    if not folder:
        return
    
scan_button = tk.Button(frame, text="Select Folder & Scan", command=browse_and_scan)
scan_button.pack()

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=25)
output_box.pack(padx=10, pady=10)
output_box.configure(state="disabled") # readonly

