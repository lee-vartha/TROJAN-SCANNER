import subprocess 
import os 
import hashlib 
import requests 
import threading 
import time 
from datetime import datetime 
from config import YARA_PATH, RULES_FOLDER, VT_API_KEY, VT_URL, UPLOAD_URL, DELAY, decide_verdict
from tkinter import Tk, ttk, scrolledtext, messagebox
import matplotlib
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def update_progress(gui, message):     
    def update():         
        gui.progress_label.config(text=message)     
        gui.root.after(0, update)

def reset_table(history_table):    
    for row in history_table.get_children():        
        history_table.delete(row)
    
def log_message(gui, message, tag=None, emoji=None):     
     def update_text():        
        gui.output_box.configure(state='normal')         
        if emoji:     
            message = f"{emoji} {message}"         
        if tag:             
            gui.output_box.insert(Tk.END, message + '\n', tag)         
        else:             
            gui.output_box.insert(Tk.END, message + '\n')         
            gui.output_box.configure(state='disabled')         
            gui.output_box.see(Tk.END)     
            gui.root.after(0, update_text)

def start_scan(gui, folder_path):     
    if getattr(gui, "scanning", False):        
        return     
    gui.scanning = True     
    gui.scan_results = []     
    gui.total_files = count_files(folder_path)  
    # Add total file count     
    gui.folder_path = folder_path  
    # Store for summary     
    gui.scan_button.pack_forget()     
    gui.cancel_button.pack(anchor="w", padx=30, pady=10, ipadx=20, ipady=4)
    gui.scan_button.config(state="disabled")     
    gui.cancel_button.config(state='normal')     
    gui.export_button.config(state='disabled')
    gui.progress_bar.pack(fill='x', pady=(5, 0))     
    gui.progress_label.pack(anchor='w')
    gui.progress_bar.start()
    gui.output_box.configure(state='normal')     
    gui.output_box.delete(1.0, Tk.END)     
    gui.output_box.configure(state='disabled')
    scan_thread = threading.Thread(target=perform_scan, args=(gui, folder_path))     
    scan_thread.daemon = True     
    scan_thread.start()

def count_files(folder_path):     
    total = 0     
    for root, dirs, files in os.walk(folder_path):         
        total += len(files)     
        return total
def perform_scan(gui, folder_path):     
    try:         
        update_progress(gui, "Step 1: Scanning files for suspicious patterns...")         
        log_message(gui, "Step 1: YARA Pattern Analysis", 'subheading')         
        log_message(gui, "-" * 40, 'muted')
        suspicious = run_yara_scan(gui, folder_path)
        if not suspicious:             
            log_message(gui, f"✅ No suspicious patterns in {gui.total_files} files. Folder is clean!", "ok")             
            file_info = {"timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"), "path": "All Files", "rules": [], "vt_malicious": 0, "vt_suspicious": 0, "verdict": "Clean"}             
            add_to_history(gui, file_info)             
            scan_complete(gui)             
            return
        log_message(gui, f"[+] Suspicious matches found: {len(suspicious)}", "warn")
        update_progress(gui, "🔍 Cross-scanning files with VirusTotal...")         
        log_message(gui, "Step 2: VirusTotal Verification", 'subheading')         
        log_message(gui, "-" * 40, 'muted')
        verify_virustotal(gui, suspicious)        
        generate_summary(gui)     
    except Exception as e:         
        log_message(gui, f"Scan error: {str(e)}", 'err')     
    finally:         
        scan_complete(gui)

def run_yara_scan(gui, target_path):     
    suspicious_files = []     
    try:        
        if not os.path.exists(target_path):
            log_message(gui, f"Target folder does not exist: {target_path}", 'err') 
            return

        yara_result = subprocess.run(             
            [YARA_PATH, '-r', RULES_FOLDER, target_path],            
            capture_output=True, text=True        
            )         
        matches = [ln for ln in yara_result.stdout.strip().splitlines() if ln]
        if not matches:             
            return []
        for line in matches:             
            try:                 
                rule, path = line.split(maxsplit=1)                 
                path = path.strip()                 
                existing = next((f for f in suspicious_files if f['path'] == path), None)                 
                if existing:                     
                    existing['rules'].append(rule)                 
                else:                     
                    file_info = {                         
                        "path": path,                         
                        "rules": [m.rule for m in matches],                         
                        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")                     
                        }                     
                    suspicious_files.append(file_info)                     
                    log_message(gui, f"⚠️ Suspicious: {os.path.basename(path)} (Rule: {rule})", "warn", "⚠️")             
            except:                 
                continue     
    except subprocess.TimeoutExpired:         
        log_message(gui, "YARA scan timed out", 'err')     
    except FileNotFoundError:         
        log_message(gui, f"YARA executable not found: {YARA_PATH}", 'err')     
    except Exception as e:         
        log_message(gui, f"YARA scan error: {str(e)}", 'err')     
        return suspicious_files
 
def verify_virustotal(gui, suspicious_files):     
    headers = {"x-apikey": VT_API_KEY}     
    for idx, file_info in enumerate(suspicious_files):         
        if not gui.scanning:             
            break         
        file_path = file_info['path']         
        log_message(gui, f"[VT Check] {os.path.basename(file_path)}", "info")         
        update_progress(gui, f"Checking file {idx+1}/{len(suspicious_files)} with VirusTotal...")
        try:             
            with open(file_path, "rb") as f:                
                sha256 = hashlib.sha256(f.read()).hexdigest()             
                response = requests.get(VT_URL + sha256, headers=headers)
            if response.status_code == 200:                 
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]                 
                mal = stats.get("malicious", 0)                 
                susp = stats.get("suspicious", 0)                 
                file_info['vt_malicious'] = mal                 
                file_info['vt_suspicious'] = susp                
                file_info['verdict'] = decide_verdict(yara_matched=True, stats=stats)
                if mal > 0:                     
                    log_message(gui, f"🚨 {mal} engines flagged as malicious!", 'warn', "🚨")                 
                elif susp > 0:                     
                    log_message(gui, f"🟡 {susp} engines marked suspicious.", 'warn', "🟡")                 
                else:                     
                    log_message(gui, f"✅ VT clear, but YARA flagged—Verdict: {file_info['verdict']}", "ok", "✅")
            elif response.status_code == 404:                 
                log_message(gui, " ‣ VirusTotal has no record of this file (hash not found).", "muted")                 
                try:                        
                    with open(file_path, "rb") as f:                            
                        upload_response = requests.post(UPLOAD_URL, headers=headers, files={"file": (os.path.basename(file_path), f)})                     
                    if upload_response.status_code == 200:                         
                        analysis_id = upload_response.json()["data"]["id"]                         
                        log_message(gui, f" Uploaded to VT (analysis_id={analysis_id})", "muted")                         
                        log_message(gui, f" Waiting {DELAY}s for results..", "muted")                         
                        time.sleep(DELAY)                         
                        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)                         
                        if result.status_code == 200:                             
                            stats = result.json()["data"]["attributes"]["stats"]                             
                            mal = stats.get("malicious", 0)                             
                            susp = stats.get("suspicious", 0)                             
                            file_info['vt_malicious'] = mal                             
                            file_info['vt_suspicious'] = susp                             
                            file_info['verdict'] = decide_verdict(yara_matched=True, stats=stats)                        
                        else:                             
                            log_message(gui, f"Could not retrieve results (HTTP {result.status_code}). Keeping YARA verdict.", "err")                             
                            file_info['vt_malicious'] = 0                             
                            file_info['vt_suspicious'] = 0                             
                            file_info['verdict'] = decide_verdict(yara_matched=True)                     
                    else:                         
                        log_message(gui, f"Upload failed (HTTP {upload_response.status_code}). Keeping YARA verdict.", "err")                         
                        file_info['vt_malicious'] = 0                         
                        file_info['vt_suspicious'] = 0                         
                        file_info['verdict'] = decide_verdict(yara_matched=True)                 
                except Exception as e:                     
                    log_message(gui, f" ⚠ Error processing file: {str(e)}", 'err')                     
                    file_info['vt_malicious'] = 0                     
                    file_info['vt_suspicious'] = 0                     
                    file_info['verdict'] = decide_verdict(yara_matched=True)             
                else:                 
                    log_message(gui, f"⚠ VT API error: HTTP {response.status_code}", 'err')                 
                    file_info['vt_malicious'] = 0                 
                    file_info['vt_suspicious'] = 0                 
                    file_info['verdict'] = decide_verdict(True)         
        except Exception as e:             
            log_message(gui, f"⚠ VT processing error: {str(e)}", 'err')             
            file_info['vt_malicious'] = 0             
            file_info['vt_suspicious'] = 0             
            file_info['verdict'] = decide_verdict(yara_matched=True)
            gui.scan_results.append(file_info)  # Append after processing         
            add_to_history(gui, file_info)         
            time.sleep(1)

def add_to_history(gui, file_info):     
    def update_history():         
        verdict = file_info.get('verdict', 'Unknown').lower()         
        gui.history_table.insert('', 0, values=(             
            file_info['timestamp'],             
            file_info['path'],             
            ", ".join(file_info['rules']),            
            file_info.get('vt_malicious', 0),             
            file_info.get('vt_suspicious', 0),            
            file_info.get('verdict', 'Unknown')         
            ), tags=(verdict,))     
        gui.root.after(0, update_history)
 
def generate_summary(gui):     
    total_files = getattr(gui, 'total_files', 0)    
    suspicious_count = len(gui.scan_results) if hasattr(gui, 'scan_results') else 0     
    malicious_count = sum(1 for f in gui.scan_results if f.get('verdict', '').lower() == 'malicious')     
    susp_count = sum(1 for f in gui.scan_results if f.get('verdict', '').lower() == 'suspicious')     
    clean_count = total_files - suspicious_count
    overall_risk = "Low" if malicious_count == 0 else "High" if malicious_count > 0 else "Moderate"     
    risk_color = {'Low': 'green', 'Moderate': 'orange', 'High': 'red'}[overall_risk]
    def update_summary():         
        for widget in gui.summary_container.winfo_children():             
            widget.destroy()
        stats_container = ttk.Frame(gui.summary_container)         
        stats_container.pack(fill='x', pady=10)

        def create_card(parent, title, value, color='black'):             
            card = ttk.Frame(parent, relief='raised', padding=10)             
            ttk.Label(card, text=title, font=('Times New Roman', 12, 'bold')).pack()             
            ttk.Label(card, text=str(value), foreground=color, font=('Times New Roman', 14)).pack()             
            return card
        
        create_card(stats_container, "Files Scanned", total_files).pack(side='left', padx=10)         
        create_card(stats_container, "Clean", clean_count, 'green').pack(side='left', padx=10)         
        create_card(stats_container, "Suspicious", susp_count, 'orange').pack(side='left', padx=10)         
        create_card(stats_container, "Malicious", malicious_count, 'red').pack(side='left', padx=10)         
        create_card(stats_container, "Overall Risk", overall_risk, risk_color).pack(side='left', padx=10)

        if total_files > 0:            
            fig = Figure(figsize=(4, 4), dpi=100)             
            ax = fig.add_subplot(111)             
            labels = ['Clean', 'Suspicious', 'Malicious']             
            sizes = [clean_count, susp_count, malicious_count]             
            colors = ['#90ee90', '#ffd700', '#ff4040']             
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=90)             
            ax.set_title('Scan Results Distribution')
            canvas = FigureCanvasTkAgg(fig, master=gui.summary_container)             
            canvas.draw()             
            canvas.get_tk_widget().pack(side='left', fill='both', expand=True, padx=20)
        summary_text = scrolledtext.ScrolledText(gui.summary_container, wrap=Tk.WORD, state='disabled', font=("Times New Roman", 10), bg="#ffffff", fg="#1e293b", height=10)         
        summary_text.pack(fill='both', expand=True, pady=10)         
        summary = f"""Scan Summary ============= Scan Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} Folder: {gui.folder_path}
Quick Tips: If threats found, quarantine them. Update YARA rules regularly! """         
        summary_text.configure(state='normal')         
        summary_text.insert(1.0, summary)         
        summary_text.configure(state='disabled')
    gui.root.after(0, update_summary)

def scan_complete(gui):     
    def update_ui():         
        gui.cancel_button.pack_forget()         
        gui.scan_button.pack(anchor="w", padx=30, pady=10, ipadx=20, ipady=4)         
        gui.progress_frame.pack_forget()         
        gui.progress_bar.pack_forget()         
        gui.progress_label.pack_forget()         
        gui.scanning = False         
        gui.scan_button.config(state='normal')         
        gui.cancel_button.config(state='disabled')         
        gui.export_button.config(state='normal')         
        gui.progress_bar.stop()         
        update_progress(gui, "🏆 Scan completed")         
        log_message(gui, "🎉 Results ready! Check the Summary tab for visuals.", 'ok', "🎉")
    gui.root.after(0, update_ui)
 