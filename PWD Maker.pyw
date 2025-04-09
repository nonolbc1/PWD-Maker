import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet
import base64
import hashlib

def derive_key(password: str) -> bytes:
    sha = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(sha)

def encrypt_message(message: str, key: str) -> str:
    if not message or not key:
        return ""
    try:
        fernet_key = derive_key(key)
        f = Fernet(fernet_key)
        return f.encrypt(message.encode()).decode()
    except Exception as e:
        return f"Erreur : {e}"

def update_output(*args):
    msg = input_text.get("1.0", tk.END).strip()
    key = key_entry.get().strip()
    output = encrypt_message(msg, key)
    output_text.config(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)
    output_text.config(state='disabled')

root = tk.Tk()
root.title("Chiffreur sécurisé")
root.geometry("600x400")
root.configure(bg="#121212")

style = ttk.Style()
style.theme_use('default')
style.configure("TLabel", background="#121212", foreground="white", font=("Segoe UI", 10))
style.configure("TEntry", fieldbackground="#1e1e1e", foreground="white", insertcolor="white")
style.configure("TText", background="#1e1e1e", foreground="white")
style.configure("TFrame", background="#121212")

mainframe = ttk.Frame(root)
mainframe.pack(padx=20, pady=20, fill="both", expand=True)

ttk.Label(mainframe, text="Initial Password:").pack(anchor='w')
input_text = tk.Text(mainframe, height=5, bg="#1e1e1e", fg="white", insertbackground="white")
input_text.pack(fill="x")
input_text.bind("<KeyRelease>", update_output)

ttk.Label(mainframe, text="Key:").pack(anchor='w', pady=(10, 0))
key_entry = ttk.Entry(mainframe)
key_entry.pack(fill="x")
key_entry.bind("<KeyRelease>", update_output)

ttk.Label(mainframe, text="Final Password:").pack(anchor='w', pady=(10, 0))
output_text = tk.Text(mainframe, height=5, bg="#1e1e1e", fg="white", insertbackground="white", state='disabled')
output_text.pack(fill="x")

root.mainloop()
