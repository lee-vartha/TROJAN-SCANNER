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

# function to double make sure the log is read-only
def set_log_readonly(state: bool):
    output_box.configure(state="disabled" if state else "normal")

# lines in the output box (doing this instead of 'output-box.insert')
def log_line(text="", tag=None): # the tag is what I created earlier - no colouring
    set_log_readonly(False)
    if tag: 
        output_box.insert(tk.END, text + "\n", tag) # have the text in the output box with a tag
    else:
        output_box.insert(tk.END, text + "\n") # otherwise have standard colouring that arent specific
    set_log_readonly(True) # makes the output box read-only again
    output_box.see(tk.END) #.see means scrolls to the end of the output box to show the latest log line
    root.update_idletasks() # updates the GUI to reflect the changes made - called idle tasks because it runs when the GUI is idle

#aesthetic reability designs:
# purely aesthetic function so theres breaklines that can be referenced easily 
def hr():
    log_line("-" * 88, "muted") #muted is one of the tags for colours

def heading(text):
    hr()
    log_line(f"= {text}", "heading") #heading is a tag so theres colours
    hr()

# added function to set scanning state
# this is used to disable the scan button when scanning is in progress
def set_scanning(on: bool):
    if on:
        scan_button.configure(state="disabled")
    else:
        scan_button.configure(state="normal")

# resetting the table in the history tab
def reset_table():
    for row in history_table.get_children():
        history_table.delete(row)
        
# adding a row to the history table
def add_row(file_path, rule, mal, susp, status): # have added extra ones, will need to update the gui to show that
    history_table.insert("", tk.END, values=(file_path, rule, mal, susp, status))

# making the definition only take the folder parameter
def scan_folder(folder_path):
    reset_table() # reset the table in the history tab
    scan_button.config(state="normal") 
    set_log_readonly(False) # makes the output box editable so I can write in it
    output_box.delete(1.0, tk.END)
    set_log_readonly(True) # makes the output box read-only again
    
    set_scanning(True) # sets the scanning state to true

    #adding a section to provide details about the scan [new section]
    # main starting output - for users to see the time, target folder/files and the rules used
    #getting the date as 'DD-MM-YYYY with the hour, minute and seconds
    ts = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    heading("Hybrid Trojan Scanner")
    log_line(f"Time: {ts}", "muted") # muted tag (grey colour)
    log_line(f"Target: {folder_path}") # referencing the folder path declaration at start of file
    log_line(f"Rules: {RULES_FILE}") # referencing the rules file declaration at start of file
    hr() # horizontal rule for aesthetics

    # instead of output_box.insert, i have added the 'heading' - differentiates different text
    #i added more detail with the title as well, so that its more user-friendly and interesting'
    heading("Step 1: Scanning files for suspicious patterns... ")

    # yara is an external source, so this is why subprocess is used
    # we reference the details added in the start, the path, rules etc.
    yara_result = subprocess.run(
        [YARA_PATH, RULES_FILE, folder_path], # referencing YARA path, rule and folder path that user chose
        capture_output=True,
        text=True
    )

    # yara_result.stdout represents the standard output
    # .strip() removes whitespace and 
    # .splitlines() splits output into list
    matches = [ln for ln in yara_result.stdout.strip().splitlines() if ln]

    # if theres no match then the output box will say nothings wrong
    if not matches:
        log_line("✅ No suspicious files found. Your folder looks clean!", "ok")
        set_scanning(False)
        log_line("\nScan Complete", "okbold")
        return

    # otherwise the box will insert
    suspicious_files = [] # empty set
    log_line(f"[+] Suspicious matches have been found: {len(matches)}", "warn")
    # for each line with the match
    for line in matches:
        #inserting "=> {line}" into the 'output_box' entry box
        # tk.END is showing the position on where the text should go - this goes at the end of the context of this string
        parts = line.split(maxsplit=1)
        rule = parts[0]
        file_path = parts[1] if len(parts) > 1 else "UNKNOWN"
        suspicious_files.append((file_path, rule))
        log_line(f"  - {rule} => {file_path}")

    # doing the same heading to 'check virustotal', just made it reference the 'heading' definition
    # made it more interesting to read too
    # in the same entry box, add 'Checking VirusTotal'
    heading("🔍 Step 2: Cross-scanning files with VirusTotal... ")

    # working with the API and inserting the headers
    headers = {"x-apikey": VT_API_KEY}

    for file_path, rule in suspicious_files:
        log_line(f"=> {file_path}", "heading2")
        try:
            # calculating the SHA256 hash 
            # open the file and read in binary mode
            with open(file_path, "rb") as f:
                # took out the file_bytes variable and just added it as parameter in sha256 variable
                sha256 = hashlib.sha256(f.read()).hexdigest()
            response = requests.get(VT_URL + sha256, headers=headers)

            # if its successful (200)
            if response.status_code == 200:
                #used to have 'data = response.json()' but decided to just add it to 'stats' to have less lines
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                mal, susp = stats["malicious"], stats["suspicious"]
                status = "Known (hash)" if (mal or susp) else "Clean"
                log_line(f"VirusTotal found {mal} malicious and {susp} suspicious reports for this file", "info")
                add_row(file_path, rule, mal, susp, status)

            # if it failed (client error - 400) - this is if it wasnt found in the database, then it would upload the file itself
            elif response.status_code == 404:
                log_line(" Not in VT. Uploading file..", "warn")

                files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
                # requests is one of the import statement used for HTTP requests - in this case, its to POST
                upload_response = requests.post(UPLOAD_URL, headers=headers, files=files)

                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()["data"]["id"]
                    log_line(f" Uploaded. Analysis ID: {analysis_id}", "muted")
                    log_line(f" Waiting {DELAY}s for results..", "muted")
                    time.sleep(DELAY)

                    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                    if result.status_code == 200:
                        stats = result.json()["data"]["attributes"]["stats"]
                        mal, susp = stats["malicious"], stats["suspicious"]
                        log_line(f" VT: {mal} malicious, {susp} suspicious", "info")
                        status = "New (uploaded)"
                        add_row(file_path, rule, mal, susp, status)
                    else:
                        log_line(f"Could not retrieve results (HTTP {result.status_code})")
                        add_row(file_path, rule, "-", "-", "Upload OK/Report pending")
                else:
                    log_line(f"Upload failed (HTTP {upload_response.status_code})", "err")
                    add_row(file_path, rule, "-", "-", "Upload failed")
            else:
                log_line(f"VT error (HTTP {response.status_code})", "err")
                add_row(file_path, rule, "-", "-", f"VT error {response.status_code}")

        except Exception as e:
            log_line(f"Error: {e}", "err")
            add_row(file_path, rule, "-", "-", "Error")

    heading("Summary")
    total = len(suspicious_files)
    mal_total = sum(int(v) if isinstance(v, int) else 0 for v in
                    [history_table.set(r, "VT Malicious") for r in history_table.get_children()])
    log_line(f"Files flagged by YARA: {total}")
    log_line(f"VirusTotal (malicious hits): {mal_total}")
    set_scanning(False)
    log_line("\n Scan complete.", "okbold")



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
        scan_folder(folder)
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
cols = ("File", "Rule", "Malicious", "Suspicious", "Status")
history_table = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)
for c, w in zip(cols, (160, 140, 100, 100, 140)):
    history_table.heading(c, text=c)
    history_table.column(c, width=w, stretch=(c == "File"))
history_table.pack(fill="x")

# vsb is vertical scrollbar
vsb = ttk.Scrollbar(table_frame, orient="vertical", command=history_table.yview)
history_table.configure(yscroll=vsb.set)

history_table.pack(side="left", fill="both", expand=True)
vsb.pack(side="right", fill="y")

root.mainloop() # starts main loop
