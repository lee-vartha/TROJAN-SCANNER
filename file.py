import tkinter as tk
from ttkthemes import ThemedTk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import os
import hashlib
import requests
import threading
import time
from datetime import datetime
from pathlib import Path

# Configuration (normally in config.py)
class Config:
    YARA_PATH = "yara64.exe"
    RULES_FILE = "rules\\trojan_rules.yar"
    VT_API_KEY = "34923601df873108e50af7f497e636c88f6087851ca5321dde99cfebec76f509"
    VT_URL = "https://www.virustotal.com/api/v3/files/"
    UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
    DELAY = 15

    @staticmethod
    def decide_verdict(yara_matched: bool, stats: dict = None) -> str:
        if stats and stats.get("malicious", 0) > 0:
            return "Malicious"
        if yara_matched:
            return "Suspicious"
        return "Clean"

class TrojanScannerGUI:
    def __init__(self, root):
        self.root = root
        self.scanning = False
        self.scan_results = []
        self.setup_window()
        self.setup_styles()
        self.create_widgets()

    def setup_window(self):
        self.root.title("TREDR - Trojan Risk Education & Detection Resource")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f8fafc')
        self.root.minsize(800, 600)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("arc")
        
        
        # Custom styles
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), 
                       background='#f8fafc', foreground='#1e293b')
        style.configure('Subtitle.TLabel', font=('Segoe UI', 11), 
                       background='#f8fafc', foreground='#64748b')
        style.configure('Action.TButton', font=('Segoe UI', 11, 'bold'), 
                       padding=(20, 12))

    def create_widgets(self):
        # Main container with padding
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill='both', expand=True)
        
        # Create tabs
        self.create_scan_tab()
        self.create_history_tab()
        self.create_about_tab()

    def create_scan_tab(self):
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Scan")
        
        # Header section
        header_frame = ttk.Frame(scan_frame)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # title = ttk.Label(header_frame, text="Hybrid Trojan Detection Tool", 
        #                  style='Title.TLabel')
        # title.pack()
        
        # subtitle = ttk.Label(header_frame, text="YARA analysis + VirusTotal hybrid verification", 
        #                     style='Subtitle.TLabel')
        # subtitle.pack(pady=(5, 0))
        
        # Control section
        control_frame = ttk.LabelFrame(scan_frame, padding=15)
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Scan controls
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill='x')
        
        self.scan_button = ttk.Button(button_frame, text="Select Folder to Scan", 
                                     style='Action.TButton', command=self.browse_and_scan)
        self.scan_button.pack(anchor='center')
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel Scan", 
                                       style='Action.TButton', command=self.cancel_scan,
                                       state='disabled')
        self.cancel_button.pack_forget()
        
        # Progress section
        progress_frame = ttk.Frame(control_frame)
        progress_frame.pack(fill='x', pady=(15, 0))
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.pack_forget()

        self.progress_label = ttk.Label(progress_frame, text="Ready to scan")
        self.progress_label.pack_forget()
        
        # Results section with tabs
        results_frame = ttk.LabelFrame(scan_frame, text="Scan Results", padding=10)
        results_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill='both', expand=True)
        
        # Console output tab
        console_frame = ttk.Frame(results_notebook)
        results_notebook.add(console_frame, text="Console Output")
        
        self.output_text = scrolledtext.ScrolledText(
            console_frame, 
            font=('Consolas', 10),
            bg="#ffffff", 
            fg='#e2e8f0',
            insertbackground='#ffffff',
            selectbackground="#8cc2c6",
            wrap=tk.WORD,
            state='disabled'
        )
        self.output_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Configure text tags for colored output
        self.setup_text_tags()
        
        # Summary tab
        summary_frame = ttk.Frame(results_notebook)
        results_notebook.add(summary_frame, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_frame,
            font=('Segoe UI', 10),
            bg='#ffffff',
            fg='#1e293b',
            wrap=tk.WORD,
            state='disabled'
        )
        self.summary_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = ttk.Frame(scan_frame)
        action_frame.pack(fill='x')
        
        self.export_button = ttk.Button(action_frame, text="Export Report", 
                                       command=self.export_report, state='disabled')
        self.export_button.pack(side='right')

    def create_history_tab(self):
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="History")
        
        # Title
        title = ttk.Label(history_frame, text="Scan History", style='Title.TLabel')
        title.pack(pady=(10, 20))
        
        # History table
        table_frame = ttk.Frame(history_frame)
        table_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        columns = ('timestamp', 'file', 'rule', 'vt_malicious', 'vt_suspicious', 'verdict')
        self.history_tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        
        # Configure columns
        column_configs = [
            ('timestamp', 'Timestamp', 140),
            ('file', 'File Path', 300),
            ('rule', 'YARA Rule', 120),
            ('vt_malicious', 'VT Malicious', 100),
            ('vt_suspicious', 'VT Suspicious', 100),
            ('verdict', 'Final Verdict', 120)
        ]
        
        for col_id, heading, width in column_configs:
            self.history_tree.heading(col_id, text=heading)
            self.history_tree.column(col_id, width=width, stretch=col_id == 'file')
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.history_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient='horizontal', command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.history_tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Clear history button
        clear_frame = ttk.Frame(history_frame)
        clear_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(clear_frame, text="Clear History", 
                  command=self.clear_history).pack(side='right')

    def create_about_tab(self):
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")
        
        about_text = """
TREDR - Trojan Risk Education & Detection Resource

This tool provides hybrid malware detection using:

• YARA Rules: Pattern-based detection for known malware signatures
• VirusTotal Integration: Cloud-based verification with multiple AV engines

Features:
- Real-time scanning progress
- Detailed scan results with color coding
- Export capabilities for reports
- Scan history tracking
- Modern, accessible interface

Security Notice:
This tool is for educational and research purposes. Always verify results
with multiple sources and follow your organization's security policies.

Configuration:
- Ensure YARA is properly installed and accessible
- Configure your VirusTotal API key in the config file
- Update YARA rules regularly for best detection rates
        """
        
        about_label = ttk.Label(about_frame, text=about_text, 
                               font=('Segoe UI', 10), justify='left')
        about_label.pack(padx=20, pady=20, anchor='nw')

    def setup_text_tags(self):
        tags = {
            'success': {'foreground': "#84cab3"},
            'warning': {'foreground': "#75b89e"},
            'error': {'foreground': '#ef4444'},
            'info': {'foreground': '#3b82f6'},
            'muted': {'foreground': '#94a3b8'},
            'heading': {'foreground': "#252627", 'font': ('Consolas', 10, 'bold')},
            'subheading': {'foreground': '#252627', 'font': ('Consolas', 10, 'bold')}
        }
        
        for tag, config in tags.items():
            self.output_text.tag_configure(tag, **config)

    def log_message(self, message, tag=None):
        """Thread-safe logging to output text widget"""
        def update_text():
            self.output_text.configure(state='normal')
            if tag:
                self.output_text.insert(tk.END, message + '\n', tag)
            else:
                self.output_text.insert(tk.END, message + '\n')
            self.output_text.configure(state='disabled')
            self.output_text.see(tk.END)
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update_text)
        else:
            update_text()

    def update_progress(self, message):
        """Update progress label"""
        def update():
            self.progress_label.config(text=message)
        
        if threading.current_thread() != threading.main_thread():
            self.root.after(0, update)
        else:
            update()

    def browse_and_scan(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self.start_scan(folder)

    def start_scan(self, folder_path):
        if self.scanning:
            return
        
        self.progress_bar.pack(fill='x', pady=(5, 0))
        self.progress_label.pack(anchor='w')

        self.scanning = True
        self.scan_results = []
        self.scan_button.pack_forget()

        self.cancel_button.pack(anchor='center', padx=(10, 0))

        # Update UI for scanning state
        self.scan_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.export_button.config(state='disabled')
        self.progress_bar.start()
        
        # Clear previous results
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(folder_path,))
        scan_thread.daemon = True
        scan_thread.start()

    def perform_scan(self, folder_path):
        try:
                        
            # Step 1: YARA Scan
            self.update_progress("Running YARA analysis...")
            self.log_message("Step 1: YARA Pattern Analysis", 'subheading')
            self.log_message("-" * 40, 'muted')
            
            suspicious_files = self.run_yara_scan(folder_path)
            
            if not suspicious_files:
                self.log_message("✓ No suspicious patterns detected", 'success')
                self.scan_complete()
                return
            
            self.log_message(f"⚠ Found {len(suspicious_files)} suspicious file(s)", 'warning')
            
            # Step 2: VirusTotal Verification
            self.update_progress("Verifying with VirusTotal...")
            self.log_message("")
            self.log_message("Step 2: VirusTotal Verification", 'subheading')
            self.log_message("-" * 40, 'muted')
            
            self.verify_with_virustotal(suspicious_files)
            
            # Generate summary
            self.generate_summary()
            
        except Exception as e:
            self.log_message(f"Scan error: {str(e)}", 'error')
        finally:
            self.scan_complete()

    def run_yara_scan(self, folder_path):
        suspicious_files = []
        
        try:
            # Check if YARA and rules exist
            if not os.path.exists(Config.RULES_FILE):
                self.log_message(f"⚠ YARA rules file not found: {Config.RULES_FILE}", 'warning')
                return suspicious_files
            
            result = subprocess.run(
                [Config.YARA_PATH, Config.RULES_FILE, folder_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            matches = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            
            for line in matches:
                try:
                    parts = line.split(maxsplit=1)
                    if len(parts) >= 2:
                        rule, file_path = parts[0], parts[1]
                        suspicious_files.append({
                            'path': file_path.strip(),
                            'rule': rule,
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                        self.log_message(f"  ► {rule}: {file_path}", 'warning')
                except:
                    continue
            
        except subprocess.TimeoutExpired:
            self.log_message("⚠ YARA scan timed out", 'warning')
        except FileNotFoundError:
            self.log_message(f"⚠ YARA executable not found: {Config.YARA_PATH}", 'warning')
        except Exception as e:
            self.log_message(f"⚠ YARA scan error: {str(e)}", 'warning')
        
        return suspicious_files

    def verify_with_virustotal(self, suspicious_files):
        if not Config.VT_API_KEY or Config.VT_API_KEY == "your_vt_api_key_here":
            self.log_message("⚠ VirusTotal API key not configured", 'warning')
            for file_info in suspicious_files:
                file_info['vt_malicious'] = 0
                file_info['vt_suspicious'] = 0
                file_info['verdict'] = Config.decide_verdict(True)
            return
        
        headers = {"x-apikey": Config.VT_API_KEY}
        
        for i, file_info in enumerate(suspicious_files):
            if not self.scanning:  # Check if scan was cancelled
                break
                
            file_path = file_info['path']
            self.update_progress(f"Checking file {i+1}/{len(suspicious_files)} with VirusTotal...")
            self.log_message(f"Checking: {os.path.basename(file_path)}", 'info')
            
            try:
                # Calculate file hash
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Query VirusTotal
                response = requests.get(f"{Config.VT_URL}{file_hash}", headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    
                    file_info['vt_malicious'] = malicious
                    file_info['vt_suspicious'] = suspicious
                    file_info['verdict'] = Config.decide_verdict(True, stats)
                    
                    if malicious > 0:
                        self.log_message(f"  ⚠ {malicious} engines detected malware", 'error')
                    elif suspicious > 0:
                        self.log_message(f"  ⚠ {suspicious} engines suspicious", 'warning')
                    else:
                        self.log_message(f"  ✓ No detections (0/{stats.get('total', 0)})", 'success')
                
                elif response.status_code == 404:
                    self.log_message("  ℹ File unknown to VirusTotal", 'muted')
                    file_info['vt_malicious'] = 0
                    file_info['vt_suspicious'] = 0
                    file_info['verdict'] = Config.decide_verdict(True)
                
                else:
                    self.log_message(f"  ⚠ VT API error: {response.status_code}", 'warning')
                    file_info['vt_malicious'] = 0
                    file_info['vt_suspicious'] = 0
                    file_info['verdict'] = Config.decide_verdict(True)
                
                # Add to history
                self.add_to_history(file_info)
                
                # Rate limiting
                time.sleep(1)  # Basic rate limiting
                
            except Exception as e:
                self.log_message(f"  ⚠ Error processing file: {str(e)}", 'error')
                file_info['vt_malicious'] = 0
                file_info['vt_suspicious'] = 0
                file_info['verdict'] = Config.decide_verdict(True)

    def add_to_history(self, file_info):
        """Add scan result to history table"""
        def update_history():
            self.history_tree.insert('', 0, values=(
                file_info['timestamp'],
                file_info['path'],
                file_info['rule'],
                file_info.get('vt_malicious', 0),
                file_info.get('vt_suspicious', 0),
                file_info.get('verdict', 'Unknown')
            ))
        
        self.root.after(0, update_history)

    def generate_summary(self):
        total_files = len(self.scan_results) if hasattr(self, 'scan_results') else 0
        
        # Create summary in summary tab
        def update_summary():
            self.summary_text.configure(state='normal')
            self.summary_text.delete(1.0, tk.END)
            
            summary = f"""Scan Summary
=============

Files Analyzed: {total_files}
Scan Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Results will be populated here after implementing full scan logic.
            """
            
            self.summary_text.insert(1.0, summary)
            self.summary_text.configure(state='disabled')
        
        self.root.after(0, update_summary)

    def cancel_scan(self):
        self.scanning = False
        self.update_progress("Scan cancelled")
        self.log_message("Scan cancelled by user", 'warning')

    def scan_complete(self):
        def update_ui():
            self.cancel_button.pack_forget()
            self.scan_button.pack(anchor='center')
            self.progress_bar.pack_forget()
            self.progress_label.pack_forget()
            self.scanning = False
            self.scan_button.config(state='normal')
            self.cancel_button.config(state='disabled')
            self.export_button.config(state='normal')
            self.progress_bar.stop()
            self.update_progress("Scan completed")
            self.log_message("", )
            self.log_message("Scan completed", 'success')
        
        self.root.after(0, update_ui)

    def export_report(self):
        content = self.output_text.get(1.0, tk.END)
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Scan Report"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Report exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)

def main():
    root = ThemedTk(theme="equilux")
    app = TrojanScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()