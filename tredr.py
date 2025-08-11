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

# -------- NOTEBOOK --------
# creating a notebook so theres different tabs in the GUI
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=12, pady=8) #packs the notebook into the root window with padding

# frame for the tabs (can be extendable)
scan_tab = ttk.Frame(notebook) # the first main page for scanning
history_tab = ttk.Frame(notebook) # file list of all the files scanned

# adding the tabs to the notebook
notebook.add(scan_tab, text="Scan") # tab is called 'Scan'
notebook.add(history_tab, text="History") # tab is called 'History'

style = ttk.Style()
style.theme_use("clam") # this is the theme of the GUI (clam is a light theme)
style.configure("TNotebook", background="#0f1320", borderwidth=0)

style.configure("Treeview", rowheight=24, font=("Arial", 10)) #treeview is the table that will be used in the history tab - the name is from the tkinter library
style.configure("Treeview.Heading", font=("Arial", 12, "bold")) # the headings of the table will be bolded
style.configure("TButton", font=("Arial", 10), padding=6) # the buttons will have a font of Arial, size 10 and padding of 6 pixels

# -------- SCAN TAB --------

# added some header rows for the scan tab
header_row = tk.Frame(scan_tab, bg="#dcdad5") # header row for the scan tab - bg is the colour of the notebook
header_row.pack(fill="x", pady=(8,6)) # packs the header row into the scan tab with padding (pack means to add the widget to the parent widget)

titles = tk.Frame(header_row, bg="#dcdad5")
titles.pack(side="left", anchor="w") # packs the titles frame to the left side of the header row (anchor means to align the widget to the west side)

# main title
title = tk.Label(scan_tab, text="Hybrid Trojan Detection Tool",
                 font=("Arial", 16, "bold"), bg="#dcdad5") # title of the scan tab
title.pack(pady=(14,6))

#subtitle going beneath the title
description = tk.Label(scan_tab, text="YARA analysis + VirusTotal hybrid verification",
                    font=("Arial", 12), bg="#dcdad5") # subtitle of the scan tab
description.pack(pady=(0, 10))

actions = tk.Frame(header_row, bg="#dcdad5") # actions frame for the scan tab
actions.pack(side="right", anchor="e") # packs the actions frame to the right side

controls = tk.Frame(scan_tab, bg="#dcdad5") # controls frame for the scan tab
controls.pack(fill="x", padx=12, pady=(0, 8)) # packs

# ----- SCAN BUTTON -----
def browse_and_scan():
    folder = filedialog.askdirectory()
    if folder:
        scan_folder(folder) # not applicable until backend logic is set
    if not folder:
        return
    
scan_button = ttk.Button(controls, text="Select Folder to Scan", command=browse_and_scan)
scan_button.pack()

# ----- OUTPUT RESULT BOX -----
output_box = scrolledtext.ScrolledText(scan_tab, wrap=tk.WORD, width=110, height=16,
                                        font=("Arial", 10), bg="#0f1320", fg="#4d555f",
                                        insertbackground="#e5e7eb", borderwidth=0)
output_box.pack(padx=14, pady=(6,16), fill="both", expand=True)
output_box.configure(state="disabled") # makes the output box read-only

# different colours for different information in the output box - more visually intruiging for the user - breaks the parts up easier too
output_box.tag_config("heading", font=("Consolas", 10, "bold"), foreground="#93c5fd")
output_box.tag_config("heading2", font=("Consolas", 10, "bold"), foreground="#a7f3d0")
output_box.tag_config("ok", foreground="#22c55e")
output_box.tag_config("okbold", font=("Consolas", 10, "bold"), foreground="#22c55e")
output_box.tag_config("warn", foreground="#f59e0b")
output_box.tag_config("info", foreground="#60a5fa")
output_box.tag_config("err", foreground="#f87171")
output_box.tag_config("muted", foreground="#94a3b8")

root.mainloop() # starts it