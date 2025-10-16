import subprocess # lets me run external program
import os # to interact with the operating system
import hashlib # to have an interface to hash files
import requests # to interact with web services/make HTTP requests
import threading # to use concurrency for running tasks
import time # getting current date and time
from datetime import datetime
from config import YARA_PATH, RULES_FILE, VT_API_KEY, VT_URL, UPLOAD_URL, DELAY, decide_verdict
import tkinter as tk
# ------ GUI HELPER --------------------------------------------
# function to double make sure the log is read-only
def set_log_readonly(output_box, state: bool):
    output_box.configure(state="disabled" if state else "normal")

# lines in the output box (doing this instead of 'output-box.insert')
def log_line(output_box, root, text="", tag=None): # the tag is what I created earlier - no colouring
    set_log_readonly(output_box, False)
    if tag: 
        output_box.insert(tk.END, text + "\n", tag) # have the text in the output box with a tag
    else:
        output_box.insert(tk.END, text + "\n") # otherwise have standard colouring that arent specific
    set_log_readonly(output_box, True) # makes the output box read-only again
    output_box.see(tk.END) #.see means scrolls to the end of the output box to show the latest log line
    root.update_idletasks() # updates the GUI to reflect the changes made - called idle tasks because it runs when the GUI is idle

def empty(output_box, root):
    log_line(output_box, root, "Scan a file to get results!", "starter")
    
#aesthetic reability designs:
# purely aesthetic function so theres breaklines that can be referenced easily 
def breaks(output_box, root):
    log_line(output_box, root, "-" * 88, "muted") #muted is one of the tags for colours

def heading(output_box, root, text):
    breaks(output_box, root)
    log_line(output_box, root, f"= {text}", "heading") #heading is a tag so theres colours
    breaks(output_box, root)

# this is used to disable the scan button when scanning is in progress
def set_scanning(scan_button, on: bool):
    if on:
        scan_button.configure(state="disabled")
    else:
        scan_button.configure(state="normal")

# resetting the table in the history tab
def reset_table(history_table):
    for row in history_table.get_children():
        history_table.delete(row)
        
# adding a row to the history table
def add_row(history_table, file_path, rule, mal="-", susp="-", status="Pending"): # have added extra ones, will need to update the gui to show that
    return history_table.insert("", tk.END, values=(file_path, rule, mal, susp, status))


# ---------------- MAIN SCANNER --------------------------
# making the definition only take the folder parameter
def scan_folder(folder_path, output_box, scan_button, root, history_table, progress, download_button, download_report):
    reset_table(history_table) # reset the table in the history tab
    progress.pack(fill="x", padx=14, pady=(0,8))
    progress.start()

    scan_button.config(state="normal") 
    set_log_readonly(output_box, False) # makes the output box editable so I can write in it
    output_box.delete(1.0, tk.END)
    set_log_readonly(output_box, True) # makes the output box read-only again

    wait = tk.BooleanVar()
    root.after(5000, lambda: wait.set(True))
    root.wait_variable(wait)

    set_scanning(scan_button, True) # sets the scanning state to true

    #adding a section to provide details about the scan [new section]
    # main starting output - for users to see the time, target folder/files and the rules used
    #getting the date as 'DD-MM-YYYY with the hour, minute and seconds
    # ts = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    # heading(output_box, root, "Hybrid Trojan Scanner")
    # log_line(output_box, root, f"Time: {ts}", "muted") # muted tag (grey colour)
    # log_line(output_box, root, f"Target: {folder_path}") # referencing the folder path declaration at start of file
    # log_line(output_box, root, f"Rules: {RULES_FILE}") # referencing the rules file declaration at start of file
    # breaks(output_box, root) # horizontal rule for aesthetics



    #----------- STEP 1 YARA -------------------------
    # instead of output_box.insert, i have added the 'heading' - differentiates different text
    #i added more detail with the title as well, so that its more user-friendly and interesting'
    heading(output_box, root, "Step 1: Scanning files for suspicious patterns... ")

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
        log_line(output_box, root, "✅ No suspicious files found. Your folder looks clean!", "ok")
        set_scanning(scan_button, False)
        log_line(output_box, root, "\nScan Complete", "okbold")
        return

    # otherwise the box will insert
    suspicious_files = [] # empty set
    log_line(output_box, root, f"[+] Suspicious matches have been found: {len(matches)}", "warn")
    # for each line with the match
    for line in matches:
        #inserting "=> {line}" into the 'output_box' entry box
        # tk.END is showing the position on where the text should go - this goes at the end of the context of this string
        rule, file_path = line.split(maxsplit=1)
        file_path = file_path.strip()
        suspicious_files.append({"path": file_path, "rule": rule})

        # log_line(f"[+] YARA flagged {len(suspicious_files)} suspicious file(s):", "warn")
        log_line(output_box, root,f"  ‣ Rule: {rule} | File: {file_path}")


    # doing the same heading to 'check virustotal', just made it reference the 'heading' definition
    # made it more interesting to read too
    # in the same entry box, add 'Checking VirusTotal'

    #----------- STEP 2 VIRUS TOTAL -------------------------
    heading(output_box, root, "🔍 Step 2: Cross-scanning files with VirusTotal... ")

    # working with the API and inserting the headers
    headers = {"x-apikey": VT_API_KEY}
    total_mal = 0

    for item in suspicious_files:
        file_path = item["path"]
        rule = item["rule"]

        # added the row_id definition when adding new updates in the history table 
        row_id = add_row(history_table, file_path, rule, "-", "-", "Pending")
        # adding more explanations
        log_line(output_box, root, f"[VT Check] {file_path}", "heading2")
        log_line(output_box, root, f" ‣ YARA flagged by rule: {rule}")

        try:
            # calculating the SHA256 hash 
            # open the file and read in binary mode
            with open(file_path, "rb") as f:
                # took out the file_bytes variable and just added it as parameter in sha256 variable
                sha256 = hashlib.sha256(f.read()).hexdigest()

        except Exception as e:
            log_line(output_box, root, f" ‣ Error reading file: {e}", "err")
            history_table.set(row_id, "status", "Suspicious")
            continue

        try:
            response = requests.get(VT_URL + sha256, headers=headers)
        except Exception as e:
            log_line(output_box, root, f" ‣ VT lookup failed: {e} - Keeping YARA verdict: Suspicious", "warn")
            history_table.set(row_id, "status", "Suspicious")
            continue

            # if its successful (200)
        if response.status_code == 200:
                #used to have 'data = response.json()' but decided to just add it to 'stats' to have less lines
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
                history_table.set(row_id, "mal", mal)
                history_table.set(row_id, "susp", susp)

                verdict = decide_verdict(yara_matched=True, stats=stats)
                history_table.set(row_id, "status", verdict)
                total_mal += mal

                if mal or susp:
                    log_line(output_box, root, f" ‣ VirusTotal reports: {mal} malicious / {susp} suspicious")
                else:
                    log_line(output_box, root, " ‣ VirusTotal reports: 0 malicious / 0 suspicious")
                if verdict == "Malicious":
                    log_line(output_box, root, f" ‣ Final Verdict: {verdict} (confirmed by VirusTotal)", "info")
                else:
                    log_line(output_box, root, f" ‣ Final Verdict: {verdict} (YARA flagged; VT has no detections)", "warn")

            # if it failed (client error - 400) - this is if it wasnt found in the database, then it would upload the file itself
        elif response.status_code == 404:
                #adding an update to the history table
                history_table.set(row_id, "status", "Suspicious")
                # adding more explanation
                log_line(output_box, root, " ‣ VirusTotal has no record of this file (hash is not found).", "muted")
                log_line(output_box, root, " ‣ Explanation: This is excepted for synthetic/test samples; we rely on YARA!", "muted")
                try:
                    files = {"file": (os.path.basename(file_path), open(file_path, "rb"))}
                    # requests is one of the import statement used for HTTP requests - in this case, its to POST
                    upload_response = requests.post(UPLOAD_URL, headers=headers, files=files)
                except Exception as e:
                    log_line(output_box, root, f" ‣ Upload failed: {e} - keeping YARA verdict: Suspicious", "warn")
                    continue

                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()["data"]["id"]
                    log_line(output_box, root, f" Uploaded to VT (analysis_id={analysis_id})", "muted")
                    log_line(output_box, root, f" Waiting {DELAY}s for results..", "muted")
                    time.sleep(DELAY)

                    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                    if result.status_code == 200:
                        stats = result.json()["data"]["attributes"]["stats"]
                        mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
                        history_table.set(row_id, "mal", mal)
                        history_table.set(row_id, "susp", susp)
                        verdict = decide_verdict(True, stats)
                        history_table.set(row_id, "status", verdict)
                        total_mal += mal
                        log_line(output_box, root, f" VT: {mal} malicious / {susp} suspicious => Veridct {verdict}", "err" if verdict == "Malicious" else "info")
                        #adding a new set of whether it was malicious or suspicious
                        if mal or susp:
                            log_line(output_box, root, f" ‣ VT analysis: {mal} malicious/ {susp} suspicious")
                        else:
                            log_line(output_box, root, " ‣ VT analysis: no detection (still unknown)")
                        log_line(output_box, root, f" ‣ Final Verdict: {verdict} (YARA-first policy)", "err" if verdict == "Malicious" else "warn")
                    else:
                        log_line(output_box, root, f"Could not retrieve results (HTTP {result.status_code}) Keeping YARA verdict: Suspicious", "err")
                        history_table.set(file_path, rule, "-", "-", "Upload OK/Report pending")
                else:
                    log_line(output_box, root, f"Upload failed (HTTP {upload_response.status_code}). Keeping YARA verdict: Suspicious", "err")
                    history_table.set(file_path, rule, "-", "-", "Upload failed")
        else:
            # changing responses and instead of 'adding a row', i am simply 'updating' it, using .set
            log_line(output_box, root, f"VT error (HTTP {response.status_code}). Keeping YARA verdict: Suspicious", "err")
            history_table.set(file_path, rule, "-", "-", f"VT error {response.status_code}")
    
    progress.stop()
    progress.pack_forget()

    download_button.pack(pady=6)
    heading(output_box, root, "Summary")

    # changingn the summary a bit (and adding a note if virustotal shows 0/0 for results)
    log_line(output_box, root, f"Files flagged by YARA: {len(suspicious_files)}", "warn")
    log_line(output_box, root, f"VirusTotal confirmed malicious: {total_mal}", "warn")
    if VT_API_KEY:
        log_line(output_box, root, "‣ Note: If VirusTotal shows 0/0, it means that the file is unknown to VT;", "muted")
    else:
        log_line(output_box, root, "‣ VirusTotal checks skipped (no API key configured)", "muted")
    set_scanning(scan_button, False)

    log_line(output_box, root, "\n Scan Completed", "okbold")