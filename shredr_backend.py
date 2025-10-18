import subprocess # lets me run external program
import os # to interact with the operating system
import hashlib # to have an interface to hash files
import requests # to interact with web services/make HTTP requests
import threading # to use concurrency for running tasks
import time # getting current date and time
import sqlite3
from database import save_scan
from datetime import datetime
from config import YARA_PATH, RULES_FOLDER, VT_API_KEY, VT_URL, UPLOAD_URL, DELAY, decide_verdict
import tkinter as tk
 
 

def update_progress(gui, message):
    """Update progress label in a thread-safe manner."""
    def update():
        gui.progress_label.config(text=message)
    if threading.current_thread() != threading.main_thread():
        gui.root.after(0, update)
    else:
        update()
 
# ------ GUI HELPER --------------------------------------------

def set_scanning(scan_button, on: bool):
    """Used to disable the scan button when scanning is in progress."""
    if on:
        scan_button.configure(state="disabled")
    else:
        scan_button.configure(state="normal")
 
def reset_table(history_table):
    """Resets the rows in the history table."""
    for row in history_table.get_children():
        history_table.delete(row)
       
def add_row(history_table, file_path, rule, mal="-", susp="-", status="Pending"):
    """Adds a row to the history table (deprecated in favor of add_to_history)."""
    return history_table.insert("", tk.END, values=(file_path, rule, mal, susp, status))
 
def log_message(gui, message, tag=None):
    """Thread-safe logging to output text widget."""
    def update_text():
        gui.output_box.configure(state='normal')
        if tag:
            gui.output_box.insert(tk.END, message + '\n', tag)
        else:
            gui.output_box.insert(tk.END, message + '\n')
        gui.output_box.configure(state='disabled')
        gui.output_box.see(tk.END)
   
    if threading.current_thread() != threading.main_thread():
        gui.root.after(0, update_text)
    else:
        update_text()
 
def start_scan(gui, folder_path):
    """Initial entry point called by the GUI to begin the scan in a new thread."""
    if getattr(gui, "scanning", False):
        return
   
    gui.scanning = True
    gui.scan_results = []
    
    # UI Setup for start
    
    gui.select_frame.pack_forget()
    gui.cancel_button.pack(anchor="w", padx=30, pady=10, ipadx=20, ipady=4)
    
    gui.cancel_button.config(state='normal')
    gui.export_button.config(state='disabled')
   
    gui.scan_button.config(state="disabled")
    gui.file_button.config(state="disabled")


    gui.progress_frame.pack(fill='x', padx=30, pady=5) # Ensure frame is packed
    gui.progress_bar.pack(side=tk.LEFT, fill='x', expand=True) # Ensure bar is packed
    gui.progress_label.pack(side=tk.LEFT, padx=(0, 10)) # Ensure label is packed
    gui.progress_bar.start()
 
    gui.output_box.configure(state='normal')
    gui.output_box.delete(1.0, tk.END)
    gui.output_box.configure(state='disabled')
 
    # Start scan in separate thread
    scan_thread = threading.Thread(target=perform_scan, args=(gui, folder_path))
    scan_thread.daemon = True
    scan_thread.start()
 
def perform_scan(gui, folder_path):
    """
    The main scan orchestration, running in a separate thread.
    Sequence: YARA -> VirusTotal Verification -> Summary.
    """
    try:
        # Step 1: YARA Scan
        update_progress(gui, "Step 1: Scanning files for suspicious patterns... ")
        log_message(gui, "Step 1: YARA Pattern Analysis", 'subheading')
        log_message(gui, "-" * 40, 'muted')
 
        suspicious = run_yara_scan(gui, folder_path)
 
        # clean_files = [f for f in os.listdir(folder_path) if not any(f == os.path.basename(s['path']) for s in suspicious)]
        if not suspicious:
            log_message(gui, "✓ No suspicious patterns detected", 'success')        
            scan_complete(gui)             
            return

        matched_rules = [file["rule"] for file in suspicious]

    
        log_message(gui, f"[+] {len(suspicious)} suspicious file{'s' if len(suspicious) != 1 else ""} found.", "warn")
        # Step 2: VirusTotal Verification
        update_progress(gui, "🔍 Cross-scanning files with VirusTotal... ")
        log_message(gui, "")
        log_message(gui, "Step 2: VirusTotal Verification", 'subheading')
        log_message(gui, "-" * 40, 'muted')
 
            
        vt_detections, vt_result = verify_virustotal(gui, suspicious)

        # verify_virustotal(gui, suspicious)

        from database import save_scan

        for f in suspicious:
            filename = os.path.basename(f["path"])
            rules = ",".join(f.get("rules", []))
            vt_detections = f.get("vt_malicious", 0)

            if vt_detections > 0:
                vt_result = "MALICIOUS"

                save_scan(filename, rules, vt_detections, vt_result)

        # save_scan(os.path.basename(folder_path), ",".join(matched_rules), vt_detections, vt_result)

        # Final Step: Generate Summary
        generate_summary(gui)


    except Exception as e:
        log_message(gui, f"Fatal Scan error: {str(e)}", 'err')
    finally:
        scan_complete(gui)
 
# ---------------- MAIN SCANNER --------------------------

def run_yara_scan(gui, folder_path):
    """
    Executes YARA via subprocess on the target folder and parses the output.
    Returns a list of dictionaries for files with YARA matches.
    """
    suspicious_files = []
    
    # Check if path is a file or a folder
    if not os.path.exists(folder_path):
        log_message(gui, f"Error: Path not found: {folder_path}", 'err')
        return []
        
    # YARA can scan a single file or a directory recursively
    yara_target = folder_path
    
    # We use RULES_FOLDER instead of RULES_FILE as per config.py snippet structure
    try:
        yara_result = subprocess.run(
            [YARA_PATH, '-r', '-w', RULES_FOLDER, yara_target],
            capture_output=True,
            text=True,
            check=False,
            timeout=120
        )
        
        # Handle subprocess errors (e.g., YARA execution failure)
        if yara_result.returncode != 0 and yara_result.stdout.strip() == "":
            if yara_result.stderr:
                log_message(gui, f"YARA Subprocess Error (Code {yara_result.returncode}): {yara_result.stderr.strip()}", 'err')
            else:
                log_message(gui, f"YARA scan failed with exit code {yara_result.returncode}.", 'err')
            return []
 
        # yara_result.stdout is the match output (e.g., 'rule_name file_path')
        matches = [ln for ln in yara_result.stdout.strip().splitlines() if ln]
 
        if not matches:
            return []
 
        # For each line with the match
        for line in matches:
            if not gui.scanning: # Allow cancellation during parsing
                break
            
            try:
                # rule name is the first word, path is the rest
                rule, path = line.split(maxsplit=1)
                path = path.strip()
                
                if not any(f['path'] == path for f in suspicious_files):
                    file_info = {
                        "path": path,
                        "rule": rule, 
                        "rules": [rule],
                        'all_rules': [rule],
                        'timestamp': datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                    }
                    suspicious_files.append(file_info)
                else:
                    for f in suspicious_files:
                        if f["path"] == path:
                            f["all_rules"].append(rule)
                            f["rules"].append(rule)
                            break
 
                log_message(gui, f"  ‣ {rule}: File: {os.path.basename(path)}")
            except ValueError:
                # Handles lines that don't match the 'rule path' format
                log_message(gui, f"YARA Output Parse Error: {line}", 'muted')
            except Exception as e:
                log_message(gui, f"YARA processing error on line: {str(e)}", 'err')
    
    except subprocess.TimeoutExpired:
        log_message(gui, "YARA scan timed out (max 120s reached).", 'err')
    except FileNotFoundError:
        log_message(gui, f"YARA executable not found: {YARA_PATH}", 'err')
    except Exception as e:
        log_message(gui, f"YARA scan error: {str(e)}", 'err')
        
    return suspicious_files
 
def verify_virustotal(gui, suspicious_files):
    """
    Calculates SHA256 and queries VirusTotal for each suspicious file.
    """
    vt_detections_total = 0
    vt_result_final = "CLEAN"\
    
    if not VT_API_KEY:
        log_message(gui, "⚠ VirusTotal API key not configured. Skipping VT check.", 'warning')
        for file_info in suspicious_files:
            file_info['vt_malicious'] = 0
            file_info['vt_suspicious'] = 0
            file_info['verdict'] = decide_verdict(True)
            gui.scan_results.append(file_info)
            add_to_history(gui, file_info)
        return
 
    headers = {"x-apikey": VT_API_KEY}
    
    for item, file_info in enumerate(suspicious_files):
        if not gui.scanning:
            break
 
        file_path = file_info['path']
 
        log_message(gui, f"[VT Check] {os.path.basename(file_path)}", "info")
        # update_progress(gui, f"Checking file {item+1}/{len(suspicious_files)} with VirusTotal...")
        update_progress(gui, f"VirusTotal: {item+1}/{len(suspicious_files)} files checked...")
        
        file_info['vt_malicious'] = 0
        file_info['vt_suspicious'] = 0
        file_info['verdict'] = decide_verdict(True) # Default to Suspicious if YARA matched
 
        try:
            # Calculate the SHA256 hash
            sha256 = ''
            with open(file_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            file_info['sha256'] = sha256
 
            # 1. Check for file hash existence (GET request)
            response = requests.get(VT_URL + sha256, headers=headers)
 
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                susp = stats.get("suspicious", 0)
 
                file_info['vt_malicious'] = mal
                file_info['vt_suspicious'] = susp
                file_info['verdict'] = decide_verdict(yara_matched=True, stats={'malicious': mal})
                verdict = file_info['verdict']
 
                if mal > 0:
                        log_message(gui, f"  🔴 {mal} engines detected MALICIOUS.", 'err')
                elif susp > 0:
                        log_message(gui, f"  🟠 {susp} engines flagged SUSPICIOUS.", 'warn')
                else:
                    log_message(gui, f"  ✅ VT Clean. Final Verdict: {verdict}", "success")
 
            # 2. Hash not found, attempt upload (POST request)
            elif response.status_code == 404:
                log_message(gui, " ‣ VT record not found (hash is new). Attempting upload...", "muted")
               
                try:
                    with open(file_path, "rb") as f:
                        upload_response = requests.post(UPLOAD_URL, 
                                                        headers=headers, 
                                                        files={"file": (os.path.basename(file_path), f)})
 
                    if upload_response.status_code == 200:
                        analysis_id = upload_response.json()["data"]["id"]
                        log_message(gui, f" Uploaded to VT (analysis_id={analysis_id})", "muted")
                        log_message(gui, f" Waiting {DELAY}s for analysis..", "muted")
                        time.sleep(DELAY)
 
                        # Retrieve analysis results (GET analysis endpoint)
                        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
                        
                        if result.status_code == 200:
                            stats = result.json()["data"]["attributes"]["stats"]
                            mal = stats.get("malicious", 0)
                            file_info['vt_malicious'] = mal
                            file_info['verdict'] = decide_verdict(yara_matched=True, stats={'malicious': mal})
                            log_message(gui, f" Analysis result: Malicious={mal}. Verdict: {file_info['verdict']}", "info")
                        else:
                            log_message(gui, f"Could not retrieve results (HTTP {result.status_code}). Keeping YARA verdict: Suspicious", "err")
                            
                    else:
                        log_message(gui, f"Upload failed (HTTP {upload_response.status_code}). Keeping YARA verdict: Suspicious", "err")
                        
                except Exception as e:
                    log_message(gui, f"  ⚠ Upload/Analysis error: {str(e)}", 'err')
                    
            # 3. Other API Errors (e.g., rate limit, invalid key)
            else:
                log_message(gui, f"⚠ VT API error: HTTP {response.status_code}. Keeping YARA verdict: Suspicious", 'err')
                
        except FileNotFoundError:
            log_message(gui, f"  File not found during VT check: {file_path}", 'err')
            file_info['verdict'] = 'Error: Missing File'
        except Exception as e:
            log_message(gui, f"⚠ VT general error on {os.path.basename(file_path)}: {str(e)}", 'err')
        
        # gui.scan_results.append(file_info)

        add_to_history(gui, file_info)
        time.sleep(1) 

    total_mal = sum(f.get('vt_malicious', 0) for f in suspicious_files)

    # if total_mal > 0:
    #     final_verdict = "MALICIOUS"
    # elif any(f.get("rules") for f in suspicious_files):
    #     final_verdict = "SUSPICIOUS"
    # else:
    #     final_verdict = "CLEAN"

    final_verdict = "MALICIOUS" if total_mal > 0 else "CLEAN"

    gui.root.after(300, lambda: refresh_history(gui))

    return total_mal, final_verdict


def add_to_history(gui, file_info):
    """Adds the final result of a file scan to the history table in the main thread."""
    def update_history():
        # Display all rules separated by comma for the table
        filename = (
            os.path.basename(file_info.get("path", ""))
            if "path" in file_info
            else file_info.get("filename", "Unknown")
        )

        rules_display = ", ".join(
            file_info.get("all_rules", [])
            or [file_info.get("rule", "")]
            or [file_info.get("yara_matches", "None")]
        )

        vt_detections = file_info.get("vt_detections", 0)
        vt_result = file_info.get("vt_result", "CLEAN")

        timestamp = file_info.get("timestamp", datetime.now().strftime("%d-%m-%Y %H:%M:%S"))

        gui.history_table.insert(
            "",
            0,
            values=(
                filename,
                rules_display,
                vt_detections,
                vt_result,
                timestamp,
            ),
        )
    
    gui.root.after(0, update_history)

def refresh_history(gui):
    import sqlite3
    from datetime import datetime
    
    for row in gui.history_table.get_children():
        gui.history_table.delete(row)
    
    try:
        conn = sqlite3.connect("history.db")
        cur = conn.cursor()

        cur.execute("SELECT filename, yara_matches, vt_detections, vt_result, timestamp FROM scans ORDER BY id DESC")
 
        for row in cur.fetchall():
            gui.history_table.insert("", "end", values=row)
        conn.close()
    except Exception as e:
        log_message(gui, f"Error loading history from database: {str(e)}", 'err')

def generate_summary(gui):
    """Generates the detailed summary in the Summary tab."""
    total_files = len(gui.scan_results) if hasattr(gui, 'scan_results') else 0
    malicious_count = sum(1 for f in gui.scan_results if f.get('verdict') == 'Malicious')
    suspicious_count = sum(1 for f in gui.scan_results if f.get('verdict') == 'Suspicious')
    clean_count = total_files - malicious_count - suspicious_count

    
    gui.summary_text.configure(state='normal')
    gui.summary_text.delete(1.0, tk.END)
    
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    gui.summary_text.insert(tk.END, "--- SHREDR Analysis Report ---\n", 'heading')
    gui.summary_text.insert(tk.END, f"Generated: {report_time}\n")
    gui.summary_text.insert(tk.END, "-" * 60 + "\n\n")

    # Overview
    gui.summary_text.insert(tk.END, "[OVERVIEW]\n", 'subheading')
    gui.summary_text.insert(tk.END, f"Total Files Analyzed: {total_files}\n")
    gui.summary_text.insert(tk.END, f"Malicious Verdicts: {malicious_count}\n", 'err')
    gui.summary_text.insert(tk.END, f"Suspicious Verdicts: {suspicious_count}\n", 'warn')
    gui.summary_text.insert(tk.END, f"Clean/Low Confidence: {clean_count}\n\n")
    
    # Detailed Results
    gui.summary_text.insert(tk.END, "[DETAILED FILE RESULTS]\n", 'subheading')
    
    if not gui.scan_results:
        gui.summary_text.insert(tk.END, "No suspicious files were processed for detailed report.\n")
    
    for f in gui.scan_results:
        verdict_tag = 'err' if f['verdict'] == 'Malicious' else ('warn' if f['verdict'] == 'Suspicious' else 'success')
        
        gui.summary_text.insert(tk.END, f"FILE: {os.path.basename(f['path'])}\n", 'file_heading')
        gui.summary_text.insert(tk.END, f"  Path: {f['path']}\n")
        gui.summary_text.insert(tk.END, f"  SHA256: {f.get('sha256', 'N/A')}\n")
        gui.summary_text.insert(tk.END, f"  SHREDR Verdict: {f['verdict']}\n", verdict_tag)
        
        gui.summary_text.insert(tk.END, "  - YARA Matches:\n")
        for rule in f.get('all_rules', [f['rule']]):
            gui.summary_text.insert(tk.END, f"    ‣ {rule}\n")
        
        gui.summary_text.insert(tk.END, "  - VirusTotal Check:\n")
        gui.summary_text.insert(tk.END, f"    ‣ Malicious Detections: {f.get('vt_malicious', 0)}\n")
        gui.summary_text.insert(tk.END, f"    ‣ Suspicious Detections: {f.get('vt_suspicious', 0)}\n")
        if f.get('sha256'):
            gui.summary_text.insert(tk.END, f"    ‣ Report Link: https://www.virustotal.com/gui/file/{f['sha256']}\n")
        
        gui.summary_text.insert(tk.END, "-" * 40 + "\n")


    gui.summary_text.configure(state='disabled')
    
def scan_complete(gui):
    """Updates the UI to the finished state after the scan thread completes."""
    def update_ui():
        # Restore scan button and hide cancel button
        gui.cancel_button.pack_forget()

        gui.select_frame.pack(fill='x')

        gui.scan_button.config(state='normal')
        gui.file_button.config(state='normal')

        # Hide progress bar elements
        gui.progress_bar.pack_forget()
        gui.progress_label.pack_forget()
        
        # Restore button states
        gui.scanning = False
        gui.scan_button.config(state='normal')
        gui.cancel_button.config(state='disabled')
        gui.export_button.config(state='normal')
        gui.progress_bar.stop()
        
        update_progress(gui, "Scan completed")
        log_message(gui,"", )
        log_message(gui, "Scan completed", 'success')
   
    # Ensure UI update runs on the main thread
    gui.root.after(0, update_ui)