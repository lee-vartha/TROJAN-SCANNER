import os
import tkinter as tk # for the GUI
import sqlite3
from ttkthemes import ThemedTk
from tkinter import filedialog, scrolledtext, ttk, messagebox
from shredr_backend import start_scan, generate_summary
import tkinter.font as tkFont
from PIL import Image, ImageTk
# -------- GUI --------
class launch_gui():
    
        # this is used to disable the scan button when scanning is in progress
    def set_scanning(self, on: bool):
        if on:
            self.scan_button.configure(state="disabled")
        else:
            self.scan_button.configure(state="normal")

    def setup_window(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title(" SHREDR - Secure Hybrid Rapid Executable Detection Resource") # main title seen in the window 
        self.root.geometry("760x500") # size of the entire screen
        self.root.configure(bg='#f8fafc')
        self.root.minsize(800, 600)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("arc") # this is the theme of the GUI (clam is a light theme)
        style.configure("Treeview", rowheight=24, font=("Times New Roman", 10)) #treeview is the table that will be used in the history tab - the name is from the tkinter library
        style.configure("Treeview.Heading", font=("Times New Roman", 12, "bold")) # the headings of the table will be bolded
        style.configure("TButton", font=("Times New Roman", 10), background="#ffffff", foreground="#485d81", padding=6) # the buttons will have a font of Lexend, size 10 and padding of 6 pixels
        style.configure('Title.TLabel', font=('Times New Roman', 18, 'bold'), 
                       background="#3c4b5a", foreground='#1e293b')
        style.configure('Subtitle.TLabel', font=('Times New Roman', 11), 
                       background='#f8fafc', foreground='#64748b')
        style.configure('Action.TButton', font=('Times New Roman', 11, 'bold'),  foreground="#485d81", 
                       padding=(20, 12))



    def create_widgets(self):
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=20)
        # -------- NOTEBOOK --------
        # creating a notebook so theres different tabs in the GUI
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True, padx=12) #packs the notebook into the root window with padding

        self.create_scan_page()
        self.create_history_page()
        self.create_about_page()

    def create_scan_page(self):
        scan_tab = ttk.Frame(self.notebook) # the first main page for scanning
        self.notebook.add(scan_tab, text="Scan") # tab is called 'Scan'

        header_row = tk.Frame(scan_tab) # header row for the scan tab - bg is the colour of the notebook
        header_row.pack(fill="x") # packs the header row into the scan tab with padding (pack means to add the widget to the parent widget)

        titles = tk.Frame(header_row)
        titles.pack(side="left", anchor="w") # packs the titles frame to the left side of the header row (anchor means to align the widget to the west side)

        # main title
        controls = ttk.LabelFrame(scan_tab) # controls frame for the scan tab
        controls.pack(fill='both', expand=True) # packs

        title_frame = ttk.Frame(controls)
        title_frame.pack(fill='x')

        
        # logo_path = "TREDR-LOGO.png"
        # logo_img = Image.open(logo_path)
        # logo_img = logo_img.resize((150, 150))
        # self.logo_photo = ImageTk.PhotoImage(logo_img)
        # logo_label = tk.Label(title_frame, image=
        # self.logo_photo, background='#f5f6f7')
        # logo_label.pack(side="right", padx=(0, 40), pady=0)



        title = tk.Label(title_frame, text="SHREDR STUDIO",
                        font=("Times New Roman", 22), background='#f5f6f7', foreground="#485d81") # title of the scan tab
        title.pack(anchor="w", padx=30, pady=(15, 0))

        # # subtitle going beneath the title
        # subtitle = tk.Label(title_frame,  text="Secure Hybrid Rapid Executable Detection Resource",
        #                     font=("Times New Roman", 13), background='#f5f6f7') # subtitle of the scan tab
        # subtitle.pack(anchor="w", padx=30)

        description = tk.Label(title_frame, wraplength=500, text="The purpose of this tool is to provide a dual-stage security triage (open-source) framework, which combines YARA speed with VirusTotal fidelity, which doubles as a transparent developer testing platform since the backend is modular to adapt to other custom rules. \nThis tool is for educational and research purposes.",
                            font=("Times New Roman", 10), background='#f5f6f7', justify="left") # subtitle of the scan tab
        description.pack(anchor="w", padx=30, pady=(0,15))

        button_frame = ttk.Frame(controls)
        button_frame.pack(fill='x', pady=(0, 0))

        self.select_frame = ttk.Frame(button_frame)
        self.select_frame.pack(side="left")

        self.scan_button = ttk.Button(self.select_frame, text="Select Folder", 
                                     style='Action.TButton',  command=lambda:self.browse_and_scan("folder"))
        self.scan_button.pack(side="left", padx=(30, 10), ipadx=20, ipady=4)

        self.file_button = ttk.Button(self.select_frame, text="Select File", 
                                     style='Action.TButton', command=lambda:self.browse_and_scan("file"))
        self.file_button.pack(side="left", ipadx=20, ipady=4)

         # Cancel button (initially hidden)

        self.cancel_button = ttk.Button(button_frame, text="Cancel Scan", 
                                style='Action.TButton', command=self.cancel_scan,
                                state='disabled')
        self.cancel_button.pack_forget()

        self.progress_frame = ttk.Frame(controls)
        self.progress_frame.pack(fill='x', pady=5, padx=30)

        self.progress_bar = ttk.Progressbar(self.progress_frame, mode='indeterminate')
        self.progress_bar.pack_forget()

        self.progress_label = ttk.Label(self.progress_frame, text="Ready to scan")
        self.progress_label.pack_forget()


        results_frame = ttk.LabelFrame(scan_tab)
        results_frame.pack(fill='both', expand=True, padx=10, pady=(0, 25))
        
        results_notebook = ttk.Notebook(controls)
        results_notebook.pack(fill='both', expand=True, padx=30, pady=(0,10))
        
        results_notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)
        # Console output tab
        console_frame = ttk.Frame(results_notebook)
        results_notebook.add(console_frame, text="Results")     

        # ----- OUTPUT RESULT BOX -----
        self.output_box = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, height=30, state='disabled',
                                                font=("Times New Roman", 10), bg="#ffffff", fg="#bdc4cc",
                                                insertbackground="#e5e7eb")
        self.output_box.pack(padx=5, pady=5, fill="both", expand=True)

        self.setup_text_tags()

                # Summary tab
        summary_frame = ttk.Frame(results_notebook)
        results_notebook.add(summary_frame, text="Detailed Summary")
        
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
        action_frame = ttk.Frame(scan_tab)
        action_frame.pack(fill='x')
        
        self.export_button = ttk.Button(action_frame, text="Export Report", 
                                       command=self.export_report, state='disabled')
        self.export_button.pack(side='right')


        # ----- SCAN BUTTON -----
    
    def browse_and_scan(self, mode=None):
        if mode == "folder":
            path = filedialog.askdirectory(title="Select a folder to scan")
        else:
            path = filedialog.askopenfilename(
                title="Select a file to scan",
                filetypes =[("Executable Files", "*.exe"), ("All Files", "*.*")]
            )
        if path:
            self.scan_mode = mode
            if mode == "folder":
                self.total_files = sum(len(files) for _, _, files in os.walk(path))
            else:
                self.total_files = 1
            
            self.scan_results = []
            self.folder_path = path
            start_scan(self, path)

    # def browse_and_scan(self):         
    #  folder = filedialog.askdirectory()         
    #  if folder:             
    #     self.folder_path = folder  
    #       # Store for summary             
    #     start_scan(self, folder)
    #     # button to download the report
    
    def download_report(self):
        content = self.output_box.get(1.0, tk.END)
        
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

    def on_tab_change(self, event):
        tab = event.widget.tab('current')['text']
        if tab == "Summary":
            generate_summary(self)

    def setup_text_tags(self):
        tags = {
            'heading': {'foreground': "#252627", 'font': ('Consolas', 10, 'bold')},
            "err": {'foreground': "#df3333"},
            "warn": {'foreground': "#327c7d", 'font': ('Consolas', 8)},
            "muted": {'foreground': "#e4ecf8"},
            "ok": {'foreground': "#262626"},
            "info": {'foreground': "#363737"},
            'subheading': {'foreground': '#252627', 'font': ('Consolas', 10, 'bold')}
        }

        for tag, config in tags.items():
            self.output_box.tag_configure(tag, **config)

    def load_history(self, history_table):
        conn = sqlite3.connect("history.db")
        cur = conn.cursor()
        cur.execute("SELECT filename, yara_matches, vt_detections, vt_result, timestamp FROM scans ORDER BY id DESC")
        for row in cur.fetchall():
            self.history_table.insert("", "end", values=row)
        conn.close()

    # -------- HISTORY TAB --------
    def create_history_page(self):
        history_tab = ttk.Frame(self.notebook) # file list of all the files scanned
        self.notebook.add(history_tab, text="History") # tab is called 'History'

        title = tk.Label(history_tab, text="Scan History",
                        font=("Times New Roman", 16), bg="#f5f6f7")
        title.pack(pady=(14,6))

        table_frame = tk.Frame(history_tab, bg="#dcdad5")
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0,10))
        # columns
        cols = ("file", "yara_matches", "vt_detections", "vt_result", "timestamp")
        self.history_table = ttk.Treeview(table_frame, columns=cols, show="headings")

        column_config = [
            ("file", "File", 260, True),
            ("yara_matches", "YARA Matches", 200, False),
            ("vt_detections", "VT Detections", 110, False),
            ("vt_result", "VT Result", 100, False),
            ("timestamp", "Timestamp", 150, True),
        ]

        #cid is column ID
        for cid, label, width, stretch in column_config:
            self.history_table.heading(cid, text=label, anchor="w")
            self.history_table.column(cid, width=width, stretch=stretch, anchor="w")

        # vsb is vertical scrollbar
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_table.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.history_table.xview)
        self.history_table.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # history_table.pack(side="left", fill="both", expand=True)
        # vsb.pack(side="right", fill="y")

        self.history_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky='ew')

        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        # Clear history button
        clear_tab = ttk.Frame(history_tab)
        clear_tab.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(clear_tab, text="Clear History", 
                  command=self.clear_history).pack(side='right')
        
        self.load_history(self.history_table)




    def create_about_page(self):
        about_frame = ttk.Frame(self.notebook)
        self.notebook.add(about_frame, text="About")
        
        about_text = """
SHREDR - Secure Hybrid Rapid Executable Detection Resource

The purpose of the triage orchestration is to manage the analysis pipeline, handle asynchronous calls
to security modules and correlate findings into a unified verdict.

The modular backend creates a developer testing ground, allowing for hot-swapping and validation of
custom YARA rules or new API connectors

• YARA Rules: Pattern-based detection for known malware signatures
• VirusTotal Integration: Cloud-based verification with multiple AV engines

The principle which governs the sequence of the triage is intelligent prioritization (resource
allocation) - YARA uses the fastest check first, and only escalate to the slower, rate-limited check
from VirusTotal if necessary.
The source of the global reputation score in SHREDR is the collective consensus gathered from the multiple
antivirus engines/security vendors which scans the file on the VT platform.


Configuration:
- Ensure YARA is properly installed and accessible
- Configure your VirusTotal API key in the config file
- Update YARA rules regularly for best detection rates
        """
        
        about_label = ttk.Label(about_frame, text=about_text, 
                               font=('Segoe UI', 10), justify='left')
        about_label.pack(padx=20, pady=20, anchor='nw')



        # about_image_path = "ABOUT-FLOW.png"
        # base_img = Image.open(about_image_path).convert("RGBA")

        # alpha = base_img.split()[3].point(lambda p: int(p * 0.25)) 
        # base_img.putalpha(alpha)

        # self.base_about_img = base_img
        # self.about_photo = ImageTk.PhotoImage(base_img)
        
        # about_label = tk.Label(
        #     about_frame, image=self.about_photo, background="#f5f6f7",
        #     bd=0, highlightthickness=0
        # )
        # about_label.pack(anchor='center', pady=(20,10))

        # def resize_about_image(event):
        #     max_width = min(event.width - 60, self.base_about_imag.width)
        #     aspect_ratio = self.base_about_img.height / self.base_about_img.width
        #     new_height = int(max_width / aspect_ratio)

        #     resized = self.base_about_img.resize((max_width, new_height), Image.LANCZOS)
        #     self.about_photo = ImageTk.PhotoImage(resized)
        #     about_label.config(image=self.about_photo)
        # about_frame.bind("<Configure>", resize_about_image)

    def clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all scan history?"):
            for item in self.history_table.get_children():
                self.history_table.delete(item)
            conn = sqlite3.connect("history.db")
            cur = conn.cursor()
            cur.execute("DELETE FROM scans")
            conn.commit()
            conn.close()


    def export_report(self):
        content = self.output_box.get(1.0, tk.END)
        
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

    def cancel_scan(self):
        self.scanning = False
        self.update_progress("Scan cancelled")
        self.log_message("Scan cancelled by user", 'warning')

