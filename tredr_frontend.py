import tkinter as tk # for the GUI
from tkinter import filedialog, scrolledtext, ttk
from tredr_backend import scan_folder
import tkinter.font as tkFont
from tredr_backend import empty
# -------- GUI --------
def launch_gui():
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
    style.configure("TNotebook", background="#0f1320", font=("Times New Roman", "bold"), borderwidth=0)

    style.configure("Treeview", rowheight=24, font=("Times New Roman", 10)) #treeview is the table that will be used in the history tab - the name is from the tkinter library
    style.configure("Treeview.Heading", font=("Times New Roman", 12, "bold")) # the headings of the table will be bolded
    style.configure("TButton", font=("Times New Roman", 10), padding=6) # the buttons will have a font of Lexend, size 10 and padding of 6 pixels

    # -------- SCAN TAB --------
    header_row = tk.Frame(scan_tab, bg="#dcdad5") # header row for the scan tab - bg is the colour of the notebook
    header_row.pack(fill="x", pady=(8,6)) # packs the header row into the scan tab with padding (pack means to add the widget to the parent widget)

    titles = tk.Frame(header_row, bg="#dcdad5")
    titles.pack(side="left", anchor="w") # packs the titles frame to the left side of the header row (anchor means to align the widget to the west side)

    # main title
    title = tk.Label(scan_tab, text="Hybrid Trojan Detection Tool",
                    font=("Times New Roman", 16, "bold"), bg="#dcdad5") # title of the scan tab
    title.pack(pady=(14,6))

    #subtitle going beneath the title
    subtitle = tk.Label(scan_tab, text="YARA analysis + VirusTotal hybrid verification",
                        font=("Times New Roman", 10), bg="#dcdad5") # subtitle of the scan tab
    subtitle.pack(pady=(0, 10))

    actions = tk.Frame(header_row, bg="#dcdad5") # actions frame for the scan tab
    actions.pack(side="right", anchor="e") # packs the actions frame to the right side

    controls = tk.Frame(scan_tab, bg="#dcdad5") # controls frame for the scan tab
    controls.pack(fill="x", padx=12, pady=(0, 8)) # packs

    # ----- SCAN BUTTON -----
    def browse_and_scan():
        folder = filedialog.askdirectory()
        if folder:
            scan_folder(folder, output_box, scan_button, root, history_table, progress, download_button, download_report)
        if not folder:
            return
        # progress.pack(pady=8, padx=14, fill="x")
        # progress.start()
        
    scan_button = ttk.Button(controls, text="Select Folder to Scan", command=browse_and_scan)
    scan_button.pack()

    progress = ttk.Progressbar(scan_tab, mode="indeterminate")
    progress.pack(fill="x", padx=14)
    progress.pack_forget()

    # ----- OUTPUT RESULT BOX -----
    output_box = scrolledtext.ScrolledText(scan_tab, wrap=tk.WORD, width=110, height=16,
                                            font=("Times New Roman", 10), bg="#0f1320", fg="#bdc4cc",
                                            insertbackground="#e5e7eb", borderwidth=0)
    output_box.pack(padx=14, pady=(6,16), fill="both", expand=True)
    output_box.configure(state="disabled") # makes the output box read-only

    report_frame = tk.LabelFrame(scan_tab, text="VT Report Explanation", fg="#ffffff")
    report_frame.pack(fill="x", padx=14, pady=4)

    toggle_btn_text = tk.StringVar(value="Show Details")

    # button to download the report
    def download_report():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            output_box.configure(state="normal")
            content = output_box.get("1.0", tk.END)
            with open(file_path, "w") as f:
                f.write(content)
            output_box.configure(state="disabled")
    

    download_button = ttk.Button(scan_tab, text="Download Report", command=download_report)
    download_button.pack(pady=6)
    download_button.pack_forget()
    # different colours for different information in the output box - more visually intruiging for the user - breaks the parts up easier too
    output_box.tag_config("starter", font=("Times New Roman", 18), foreground="#c1c7ce")
    output_box.tag_config("heading", font=("Times New Roman", 10, "bold"), foreground="#93c5fd")
    output_box.tag_config("heading2", font=("Times New Roman", 10, "bold"), foreground="#a7f3d0")
    output_box.tag_config("ok", foreground="#22c55e")
    output_box.tag_config("okbold", font=("Times New Roman", 10, "bold"), foreground="#22c55e")
    output_box.tag_config("warn", foreground="#f59e0b")
    output_box.tag_config("info", foreground="#60a5fa")
    output_box.tag_config("err", foreground="#f87171")
    output_box.tag_config("muted", foreground="#e4ecf8")
    output_box.tag_config("small",font=("Times New Roman", 12) )

    # -------- HISTORY TAB --------
    title = tk.Label(history_tab, text="Scan History",
                    font=("Times New Roman", 16), bg="#dcdad5")
    title.pack(pady=(14,6))

    table_frame = tk.Frame(history_tab, bg="#dcdad5")
    table_frame.pack(fill="both", expand=True, padx=14, pady=(4, 6))
    # columns
    cols = ("file", "rule", "mal", "susp", "status")
    history_table = ttk.Treeview(table_frame, columns=cols, show="headings", height=8)

    for cid, label, width, stretch in [
        ("file", "File", 260, True),
        ("rule", "Rule", 140, False),
        ("mal", "VT Malicious", 110, False),
        ("susp", "VT Suspicious", 110, False),
        ("status", "Verdict", 140, False),
    ]:
        history_table.heading(cid, text=label, anchor="w")
        history_table.column(cid, width=width, stretch=stretch, anchor="w")

    # vsb is vertical scrollbar
    vsb = ttk.Scrollbar(table_frame, orient="vertical", command=history_table.yview)
    history_table.configure(yscrollcommand=vsb.set)

    # history_table.pack(side="left", fill="both", expand=True)
    # vsb.pack(side="right", fill="y")

    history_table.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    table_frame.grid_columnconfigure(0, weight=1)
    table_frame.grid_rowconfigure(0, weight=1)

    empty(output_box, root)

    explanation = tk.Label(history_tab,
                           text="\n Explanation: 'Malicious' is the number of antivirus engines that flagged the file."
                           " If it is 0, VT has not found anything harmful. \n"
                           "If both Malicious and Suspicious are 0, the file may either be clean or it is unknown to VirusTotal",
                           wraplength=700, justify="left", font=("Times New Roman", 10), bg="#dcdad5", fg="#374151")
    explanation.pack(padx=14, pady=(0,8), anchor="w")

    root.mainloop() # starts main loop
    return tk, output_box, scan_button, root, history_table
