import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
import subprocess

class CustomEntry(tk.Entry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config(bg="#333333", fg="#CCCCCC", insertbackground="#CCCCCC")

class CustomListbox(tk.Listbox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config(bg="#333333", fg="#CCCCCC", selectbackground="#1976D2", selectforeground="#FFFFFF")

class CustomButton(tk.Button):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config(bg="#388E3C", fg="#FFFFFF", activebackground="#4CAF50", activeforeground="#FFFFFF")

class OTPManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OTP Manager")
        self.geometry("400x500")
        self.configure(bg="#1E1E1E")

        self.db_path = 'otp.db'
        if not os.path.exists(self.db_path):
            self.installation_page()
        else:
            self.dashboard_page()

    def installation_page(self):
        self.clear_widgets()

        self.instructionLabel = tk.Label(self, text="Welcome to OTP Manager!", bg="#1E1E1E", fg="#CCCCCC", font=("Arial", 12))
        self.instructionLabel.pack(pady=20)

        self.installButton = CustomButton(self, text="Install OTP Manager", command=self.install_server, font=("Arial", 12))
        self.installButton.pack(pady=10)

    def install_server(self):
        with sqlite3.connect(self.db_path) as db:
            cursor = db.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS otp_secrets (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT DEFAULT 'none',
                    secret TEXT NOT NULL,
                    otp_type TEXT NOT NULL,
                    refresh_time INTEGER NOT NULL,
                    company_id INTEGER,
                    FOREIGN KEY (company_id) REFERENCES companies (id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    last_login_time TEXT,
                    session_token TEXT,
                    is_admin INTEGER DEFAULT 0,
                    enable_pagination INTEGER DEFAULT 0,
                    show_timer INTEGER DEFAULT 0,
                    show_otp_type INTEGER DEFAULT 1,
                    show_content_titles INTEGER DEFAULT 1,
                    alert_color TEXT DEFAULT 'alert-primary',
                    text_color TEXT DEFAULT '#FFFFFF',
                    show_emails INTEGER DEFAULT 0,
                    show_company INTEGER DEFAULT 0
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS companies (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    kundennummer TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY,
                    logins_today INTEGER NOT NULL,
                    times_refreshed INTEGER NOT NULL,
                    date TEXT NOT NULL
                )
            """)
            
            cursor.execute("""
                INSERT INTO users (id, username, password, is_admin) 
                VALUES (?, ?, ?, ?)
            """, (1, "admin", "1234", 1))
            
            db.commit()
        
        self.add_user_company_page()

    def add_user_company_page(self):
        self.clear_widgets()

        self.usernameLabel = tk.Label(self, text="Username:", bg="#1E1E1E", fg="#CCCCCC", font=("Arial", 12))
        self.usernameLabel.pack(pady=(20, 0))

        self.usernameInput = CustomEntry(self)
        self.usernameInput.pack()

        self.passwordLabel = tk.Label(self, text="Password:", bg="#1E1E1E", fg="#CCCCCC", font=("Arial", 12))
        self.passwordLabel.pack(pady=10)

        self.passwordInput = CustomEntry(self, show="*")
        self.passwordInput.pack()

        addUserButton = CustomButton(self, text="Add User", command=self.add_user, font=("Arial", 12))
        addUserButton.pack(pady=10)

        self.userListLabel = tk.Label(self, text="Added Users:", bg="#1E1E1E", fg="#CCCCCC", font=("Arial", 12))
        self.userListLabel.pack(pady=10)

        self.userListbox = CustomListbox(self, font=("Arial", 12), selectmode=tk.SINGLE)
        self.userListbox.pack(fill=tk.BOTH, expand=True)

        doneButton = CustomButton(self, text="Done", command=self.dashboard_page, font=("Arial", 12))
        doneButton.pack(pady=10)

    def add_user(self):
        username = self.usernameInput.get()
        password = self.passwordInput.get()

        with sqlite3.connect(self.db_path) as db:
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO users (username, password) 
                VALUES (?, ?)
            """, (username, password))
            db.commit()

        self.userListbox.insert(tk.END, username)
        messagebox.showinfo("User Added", "User added successfully.")
        self.usernameInput.delete(0, 'end')
        self.passwordInput.delete(0, 'end')

    def dashboard_page(self):
        self.clear_widgets()

        self.statusLabel = tk.Label(self, text="Server Status: Stopped", bg="#1E1E1E", fg="#CCCCCC", font=("Arial", 12))
        self.statusLabel.pack(pady=(50, 0))

        startButton = CustomButton(self, text="Start Server", command=self.start_server, font=("Arial", 12))
        startButton.pack(pady=10)

        stopButton = CustomButton(self, text="Stop Server", command=self.stop_server, font=("Arial", 12))
        stopButton.pack(pady=10)

    def start_server(self):
        try:
            subprocess.Popen(["python", "app.py"], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            messagebox.showinfo("Server Started", "Server started successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error starting server: {e}")

    def stop_server(self):
        os.system('TASKKILL /F /IM cmd.exe')

    def clear_widgets(self):
        for widget in self.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    app = OTPManagerApp()
    app.mainloop()
