import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import filedialog
import hashlib
import os
import sys
import base64
from cryptography.fernet import Fernet
import winsound
from pathlib import Path

logo_path = r"icon.ico"

def resource_path(relative_path):
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

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

def decrypt_message(encrypted_message: str, key: str) -> str:
    if not encrypted_message or not key:
        return ""
    try:
        fernet_key = derive_key(key)
        f = Fernet(fernet_key)
        return f.decrypt(encrypted_message.encode()).decode()
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

def update_decrypt_output(*args):
    encrypted_msg = input_text_decrypt.get("1.0", tk.END).strip()
    key = key_entry_decrypt.get().strip()
    output = decrypt_message(encrypted_msg, key)
    output_text_decrypt.config(state='normal')
    output_text_decrypt.delete("1.0", tk.END)
    output_text_decrypt.insert(tk.END, output)
    output_text_decrypt.config(state='disabled')

def save_to_yaml(initial, key, final):
    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
    warn = messagebox.askyesno("Warning !", 
        "Enregistrer ce fichier peut exposer vos données à un risque si le fichier est volé ou piraté.\n\n"
        "Souhaitez-vous vraiment continuer ?",
        icon=messagebox.WARNING)

    if warn:
        filepath = filedialog.asksaveasfilename(defaultextension=".yml",
                                                filetypes=[("YAML files", "*.yml")])
        if filepath:
            with open(filepath, "w", encoding="utf-8") as file:
                file.write(f"Initial: {initial}\nKey: {key}\nFinal: {final}")
            messagebox.showinfo("Sauvegarde", "Fichier sauvegardé avec succès.")

root = tk.Tk()
root.title("PWD Maker")
root.geometry("600x400")
root.configure(bg="#121212")

style = ttk.Style()
style.theme_use('default')
style.configure("TLabel", background="#121212", foreground="white", font=("Segoe UI", 10))
style.configure("TEntry", fieldbackground="#1e1e1e", foreground="white", insertcolor="white")
style.configure("TText", background="#1e1e1e", foreground="white")
style.configure("TFrame", background="#121212")
style.configure("TNotebook", background="#121212")
style.configure("TNotebook.Tab", background="#1e1e1e", foreground="white", font=("Segoe UI", 10))

tab_control = ttk.Notebook(root)
tab_control.pack(padx=10, pady=10, fill="both", expand=True)

tab1 = ttk.Frame(tab_control)
tab_control.add(tab1, text="Cryptage")
tab2 = ttk.Frame(tab_control)
tab_control.add(tab2, text="Décryptage")

mainframe = ttk.Frame(tab1)
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

ttk.Button(tab1, text="Sauvegarder", command=lambda: save_to_yaml(input_text.get("1.0", tk.END), key_entry.get(), output_text.get("1.0", tk.END))).pack(pady=5)

decrypt_frame = ttk.Frame(tab2)
decrypt_frame.pack(padx=20, pady=20, fill="both", expand=True)

ttk.Label(decrypt_frame, text="Encrypted Password:").pack(anchor='w')
input_text_decrypt = tk.Text(decrypt_frame, height=5, bg="#1e1e1e", fg="white", insertbackground="white")
input_text_decrypt.pack(fill="x")
input_text_decrypt.bind("<KeyRelease>", update_decrypt_output)

ttk.Label(decrypt_frame, text="Key:").pack(anchor='w', pady=(10, 0))
key_entry_decrypt = ttk.Entry(decrypt_frame)
key_entry_decrypt.pack(fill="x")
key_entry_decrypt.bind("<KeyRelease>", update_decrypt_output)

ttk.Label(decrypt_frame, text="Decrypted Password:").pack(anchor='w', pady=(10, 0))
output_text_decrypt = tk.Text(decrypt_frame, height=5, bg="#1e1e1e", fg="white", insertbackground="white", state='disabled')
output_text_decrypt.pack(fill="x")

ttk.Button(tab2, text="Sauvegarder", command=lambda: save_to_yaml(input_text_decrypt.get("1.0", tk.END), key_entry_decrypt.get(), output_text_decrypt.get("1.0", tk.END))).pack(pady=5)

icon_path = resource_path(logo_path)

if Path(icon_path).is_file():
    root.iconbitmap(icon_path)

root.mainloop()
