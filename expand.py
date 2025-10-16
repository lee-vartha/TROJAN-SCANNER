import tkinter as tk

def add_expandable_section(parent, title, content_lines, root):
    container = tk.Frame(parent, bg="#0f1320")
    container.pack(fill="x", anchor="w", pady=1)

    def toggle():
        if content_frame.winfo_ismapped():
            content_frame.pack_forget()
            toggle_btn.config(text=f"[+] {title}")
        else:
            content_frame.pack(fill="x", padx=12)
            toggle_btn.config(text=f"[-] {title}")
        root.update_idletasks()
    
    toggle_btn = tk.Button(container, text=f"[+] {title}", font=("Times New Roman", 10, "bold"),
                            bg="#1f2937", fg="#e5e7eb", relief="flat", anchor="w", command=toggle)
    toggle_btn.pack(fill="x")

    content_frame = tk.Frame(container, bg="#1e1e2f")
    for line in content_lines:
        lbl = tk.Label(content_frame, text=line, font=("Times New Roman", 10), 
                        bg="#1e1e2f", fg="#d1d5db", anchor="w", justify="left")
        lbl.pack(anchor="w")
