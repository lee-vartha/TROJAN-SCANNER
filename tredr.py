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

def scan_folder(folder_path, output_box):
    output_box.configure(state="normal")
    output_box.delete(1.0, tk.END)
    scan_button.config(state="disabled")
    output_box.insert(tk.END, "[+] Running YARA scan...\n")

    yara_result = subprocess.run(
        [YARA_PATH, RULES_FILE, folder_path],
        capture_output=True,
        text=True
    )

    # yara_result.stdout represents the standard output
    # .strip() removes whitespace and 
    # .splitlines() splits output into list
    matches = yara_result.stdout.strip().splitlines()

    # if theres no match then the output box will say nothings wrong
    if not matches or matches == ['']:
        output_box.insert(tk.END, "[-] No suspicious files detected,\n")
        done_scanning()
        return

    # otherwise the box will insert
    output_box.insert(tk.END, "[+] YARA matches found: \n")
    # creates an empty set, which will list out unordered items
    suspicious_files = set()
    # for each line with the match
    for line in matches:
        #inserting "=> {line}" into the 'output_box' entry box
        # tk.END is showing the position on where the text should go - this goes at the end of the context of this string
        output_box.insert(tk.END, f"=> {line}\n")
        parts = line.split()
        # if the length of everything is more than 2 then add the second element
        if len(parts) >= 2:
            suspicious_files.add(parts[1])

    # in the same entry box, add 'Checking VirusTotal'
    output_box.insert(tk.END, "\n[+] Checking VirusTotal... \n")

    # working with the API and inserting the headers
    headers = {"x-apikey": VT_API_KEY}


    for file_path in suspicious_files:
        output_box.insert(tk.END, f"\n => {file_path}\n")
        try:
            # calculating the SHA256 hash 
            # open the file and read in binary mode
            with open(file_path, "rb") as f:
                file_bytes = f.read()
                sha256 = hashlib.sha256(file_bytes).hexdigest()
            response = requests.get(VT_URL + sha256, headers=headers)

            # if its successful (200)
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                output_box.insert(tk.END, f"VT Detection: {stats['malicious']} malicious, {stats['suspicious']} suspicious\n")

            # if it failed (client error - 400)
            elif response.status_code == 404:
                output_box.insert(tk.END, "Not found in VT database. Uploading file...\n")

                files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
                upload_response = requests.post(UPLOAD_URL, headers=headers, files=files)

                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()["data"]["id"]
                    output_box.insert(tk.END, f"Uploaded. Analysis ID: {analysis_id}\n Waiting for analysis ({DELAY} secs)...\n")
                    time.sleep(DELAY)

                    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                    if result.status_code == 200:
                        stats = result.json()["data"]["attributes"]["stats"]
                        output_box.insert(tk.END, f"VT Detection: {stats['malicious']} malicious, {stats['suspicious']} suspicious \n")
                    else:
                        output_box.insert(tk.END, f"Couldnt retrieve results: {result.status_code}\n")
                else:
                    output_box.insert(tk.END, f"Upload failed: {upload_response.status_code}\n")
            else:
                output_box.insert(tk.END, f"VT error: {response.status_code}\n")

        except Exception as e:
            output_box.insert(tk.END, f"Error: {e}\n")

    done_scanning()

def done_scanning():
    scan_button.config(state="normal")
    output_box.insert(tk.END, "\n Scan Complete.")
    output_box.configure(state="disabled")


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
header_row = tk.Frame(scan_tab, bg="#dcdad5") # header row for the scan tab - bg is the colour of the notebook
header_row.pack(fill="x", pady=(8,6)) # packs the header row into the scan tab with padding (pack means to add the widget to the parent widget)

titles = tk.Frame(header_row, bg="#dcdad5")
titles.pack(side="left", anchor="w") # packs the titles frame to the left side of the header row (anchor means to align the widget to the west side)

# main title
title = tk.Label(scan_tab, text="Hybrid Trojan Detection Tool",
                 font=("Arial", 16, "bold"), bg="#dcdad5") # title of the scan tab
title.pack(pady=(14,6))

#subtitle going beneath the title
subtitle = tk.Label(scan_tab, text="YARA analysis + VirusTotal hybrid verification",
                    font=("Arial", 12), bg="#dcdad5") # subtitle of the scan tab
subtitle.pack(pady=(0, 10))

actions = tk.Frame(header_row, bg="#dcdad5") # actions frame for the scan tab
actions.pack(side="right", anchor="e") # packs the actions frame to the right side

controls = tk.Frame(scan_tab, bg="#dcdad5") # controls frame for the scan tab
controls.pack(fill="x", padx=12, pady=(0, 8)) # packs

# ----- SCAN BUTTON -----
def browse_and_scan():
    folder = filedialog.askdirectory()
    if folder:
        scan_folder(folder, output_box) # not applicable until backend logic is set
    if not folder:
        return
    
scan_button = ttk.Button(controls, text="Select Folder to Scan", command=browse_and_scan)
scan_button.pack(side="left", padx=8, anchor="e")

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

# -------- HISTORY TAB --------
title = tk.Label(history_tab, text="Scan History",
                 font=("Arial", 16, "bold"), bg="#dcdad5")
title.pack(pady=(14,6))

table_frame = tk.Frame(history_tab, bg="#dcdad5")
table_frame.pack(fill="both", expand=True, padx=14, pady=(4, 6))
# columns
cols = ("File", "Rule", "Date", "Status")
history_table = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
for c, w in zip(cols, (160, 140, 140, 140)):
    history_table.heading(c, text=c)
    history_table.column(c, width=w, stretch=(c == "File"))
history_table.pack(fill="x")

# vsb is vertical scrollbar
vsb = ttk.Scrollbar(table_frame, orient="vertical", command=history_table.yview)
history_table.configure(yscroll=vsb.set)

history_table.pack(side="left", fill="both", expand=True)
vsb.pack(side="right", fill="y")

root.mainloop() # starts main loop
