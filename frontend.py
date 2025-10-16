import tkinter as tk 
from ttkthemes import ThemedTk 
from tkinter import filedialog, scrolledtext, ttk, messagebox 
from PIL import Image, ImageTk 
import tkinter.font as tkFont 
from matplotlib.figure import Figure 
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg 
import backend  # Import backend for scan function

# -------- GUI -------- 
class LaunchGUI():     
    def set_scanning(self, on: bool):         
        if on:             
            self.scan_button.configure(state="disabled")         
        else:             
            self.scan_button.configure(state="normal")

    def setup_window(self):         
        self.root = ThemedTk(theme="equilux")         
        self.root.title("TREDR - Trojan Risk Education & Detection Resource")        
        self.root.geometry("760x500")         
        self.root.configure(bg='#f8fafc')         
        self.root.minsize(800, 600)

    def setup_styles(self):         
        style = ttk.Style()        
        style.theme_use("arc")        
        style.configure("Treeview", rowheight=24, font=("Times New Roman", 10))        
        style.configure("Treeview.Heading", font=("Times New Roman", 12, "bold"))        
        style.configure("TButton", font=("Times New Roman", 10), padding=6)       
        style.configure('Title.TLabel', font=('Times New Roman', 18, 'bold'), background="#3c4b5a", foreground='#1e293b')  
        style.configure('Subtitle.TLabel', font=('Times New Roman', 11), background='#f8fafc', foreground='#64748b')      
        style.configure('Action.TButton', font=('Times New Roman', 11, 'bold'), foreground="#000000",   padding=(20, 12))

    def create_widgets(self):         
        main_container = ttk.Frame(self.root)        
        main_container.pack(fill='both', expand=True, padx=20, pady=20)   
        self.notebook = ttk.Notebook(main_container)     
        self.notebook.pack(fill="both", expand=True, padx=12)
        self.create_scan_page()       
        self.create_history_page()       
        self.create_about_page()

    def create_scan_page(self):        
        scan_tab = ttk.Frame(self.notebook)       
        self.notebook.add(scan_tab, text="Scan")
        header_row = tk.Frame(scan_tab)      
        header_row.pack(fill="x")
        titles = tk.Frame(header_row)        
        titles.pack(side="left", anchor="w")
        controls = ttk.LabelFrame(scan_tab)        
        controls.pack(fill='both', expand=True)
        button_frame = ttk.Frame(controls)        
        button_frame.pack(fill='x')
        logo_path = "TREDR-LOGO.png"        
        logo_img = Image.open(logo_path).resize((160, 160))      
        self.logo_photo = ImageTk.PhotoImage(logo_img)       
        logo_label = tk.Label(button_frame, image=self.logo_photo, background='#f5f6f7')       
        logo_label.pack(side="right", padx=(0, 40))
        title = tk.Label(button_frame, text="TREDR STUDIO", font=("Times New Roman", 22), background='#f5f6f7')       
        title.pack(anchor="w", padx=30, pady=(10, 0))

        subtitle = tk.Label(button_frame, text="Trojan Risk Education & Detection Resource",  font=("Times New Roman", 13), background='#f5f6f7')         
        subtitle.pack(anchor="w", padx=30)
        description = tk.Label(button_frame, wraplength=450, text="Lorem ipsum dolor sit amet...",  font=("Times New Roman", 10), background='#f5f6f7', justify="left")         
        description.pack(anchor="w", padx=30, pady=5)
        self.scan_button = ttk.Button(button_frame, text="Select Folder to Scan",                                      
                                      style='Action.TButton', command=self.browse_and_scan)        
        self.scan_button.pack(anchor="w", padx=30, pady=10, ipadx=20, ipady=4)
        self.cancel_button = ttk.Button(button_frame, text="Cancel Scan",                               
                                          style='Action.TButton', command=self.cancel_scan, state='disabled')        
        self.cancel_button.pack_forget()

        self.progress_frame = ttk.Frame(controls)         
        self.progress_frame.pack(fill='x', pady=5, padx=30)
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate')        
        self.progress_bar.pack_forget()
        self.progress_label = ttk.Label(self.progress_frame, text="Ready to scan")         
        self.progress_label.pack_forget()
        results_notebook = ttk.Notebook(controls)         
        results_notebook.pack(fill='both', expand=True, padx=30)
        # Console output tab        
        console_frame = ttk.Frame(results_notebook)        
        results_notebook.add(console_frame, text="Results")         
        self.output_box = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, state='disabled', font=("Times New Roman", 10), bg="#ffffff", fg="#bdc4cc",                                                 insertbackground="#e5e7eb")         
        self.output_box.pack(padx=14, pady=(8,10), fill="both", expand=True)        
        self.setup_text_tags()
        # Summary tab with dashboard        
        summary_frame = ttk.Frame(results_notebook)         
        results_notebook.add(summary_frame, text="Summary")         
        self.summary_container = ttk.Frame(summary_frame) 
         # Container for dashboard       
        self.summary_container.pack(fill='both', expand=True, padx=5, pady=5)
        action_frame = ttk.Frame(scan_tab)         
        action_frame.pack(fill='x')         
        self.export_button = ttk.Button(action_frame, text="Export Report", command=self.download_report, state='disabled')        
        self.export_button.pack(side='right')
    def browse_and_scan(self):         
     folder = filedialog.askdirectory()         
     if folder:             
          self.folder_path = folder  
          # Store for summary             
          backend.start_scan(self, folder)
    def download_report(self):         
        content = self.output_box.get(1.0, tk.END)         
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",  filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title="Export Scan Report")        
        if file_path:             
            try:                 
                with open(file_path, 'w', encoding='utf-8') as f:                    
                     f.write(content)                 
                     messagebox.showinfo("Success", f"Report exported to:\n{file_path}")            
            except Exception as e:                 
                messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")

    def setup_text_tags(self):         
        tags = {             
            'heading': {'foreground': "#252627", 'font': ('Consolas', 10, 'bold')}, 
            "err": {'foreground': "#df3333"},            
            "warn": {'foreground': "#6dced0", 'font': ('Consolas', 8)},             
            "muted": {'foreground': "#e4ecf8"},             
            "ok": {'foreground': "#262626"},            
            "info": {'foreground': "#959999"},            
            'subheading': {'foreground': '#252627', 'font': ('Consolas', 10, 'bold')}         
            }         
        for tag, config in tags.items():             
             self.output_box.tag_configure(tag, **config)

    def create_history_page(self):         
        history_tab = ttk.Frame(self.notebook)        
        self.notebook.add(history_tab, text="History")
        title = tk.Label(history_tab, text="Scan History",   
                                               font=("Times New Roman", 16), bg="#dcdad5")        
        title.pack(pady=(14,6))
        table_frame = tk.Frame(history_tab, bg="#dcdad5")         
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))         
        cols = ("timestamp", "file", "rule", "mal", "susp", "status")         
        self.history_table = ttk.Treeview(table_frame, columns=cols, show="headings")
        column_config = [             
            ("timestamp", "Timestamp", 150, True),            
            ("file", "File", 260, True),             
            ("rule", "Rule", 140, False),                      
            ("mal", "VT Malicious", 110, False),             
            ("susp", "VT Suspicious", 110, False),             
            ("status", "Verdict", 140, False),         
            ]
        for cid, label, width, stretch in column_config:             
            self.history_table.heading(cid, text=label, anchor="w")             
            self.history_table.column(cid, width=width, stretch=stretch, anchor="w")
            self.history_table.tag_configure('malicious', background='#ffcccc', foreground='#000000')         
            self.history_table.tag_configure('suspicious', background='#fff2cc', foreground='#000000')         
            self.history_table.tag_configure('clean', background='#e6ffe6', foreground='#000000')         
            self.history_table.tag_configure('unknown', background='#f0f0f0', foreground='#000000')
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_table.yview)         
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.history_table.xview)         
        self.history_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.history_table.grid(row=0, column=0, sticky="nsew")         
        vsb.grid(row=0, column=1, sticky="ns")         
        hsb.grid(row=1, column=0, sticky='ew')
        table_frame.grid_columnconfigure(0, weight=1)         
        table_frame.grid_rowconfigure(0, weight=1)
        clear_tab = ttk.Frame(history_tab)         
        clear_tab.pack(fill='x', padx=10, pady=10)         
        ttk.Button(clear_tab, text="Clear History", command=self.clear_history).pack(side='right')

    def create_about_page(self):         
        about_frame = ttk.Frame(self.notebook)         
        self.notebook.add(about_frame, text="About")        
        about_text = """ TREDR - Trojan Risk Education & Detection Resource
This tool provides hybrid malware detection using: • YARA Rules: Pattern-based detection for known malware signatures • VirusTotal Integration: Cloud-based verification with multiple AV engines
Features: - Real-time scanning progress - Detailed scan results with color coding - Export capabilities for reports - Scan history tracking - Modern, accessible interface
Security Notice: This tool is for educational and research purposes. Always verify results with multiple sources and follow your organization's security policies.
Configuration: - Ensure YARA is properly installed and accessible - Configure your VirusTotal API key in the config file - Update YARA rules regularly for best detection rates         """         
        about_label = ttk.Label(about_frame, text=about_text, font=('Segoe UI', 10), justify='left')         
        about_label.pack(padx=20, pady=20, anchor='nw')
 
    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            for item in self.history_table.get_children():
                self.history_table.delete(item)

    def cancel_scan(self):
        if hasattr(self, 'scanning') and self.scanning:
            self.scanning = False
            self.update_progress("Scan cancelled")
            self.log_message("Scan cancelled by user", 'warning')

    def update_progress(self, message):
        def update():
            self.progress_label.config(text=message)
        self.root.after(0, update)

    def log_message(self, message, tag=None, emoji=None):
        def update_text():
            self.output_box.configure(state='normal')
            if emoji:
                message = f"{emoji} {message}"
            if tag:
                self.output_box.insert(tk.END, message + '\n', tag)
            else:
                self.output_box.insert(tk.END, message + '\n')
            self.output_box.configure(state='disabled')
            self.output_box.see(tk.END)
        self.root.after(0, update_text)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":

    app = LaunchGUI()

    app.run()
 