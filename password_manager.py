import tkinter as tk
from tkinter import messagebox, filedialog
import tkinter.ttk as ttk
import requests
import os
import sqlite3
from cryptography.fernet import Fernet
import json
import logging
import re

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize encryption key
def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("key.key", "rb").read()

if not os.path.exists("key.key"):
    write_key()

key = load_key()
fernet = Fernet(key)

# Create the database or connect to one
conn = sqlite3.connect('password_manager.db')
c = conn.cursor()

# Create or update the users table with the correct schema
def update_users_table():
    c.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in c.fetchall()]
    if "file_path" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN file_path TEXT")
        conn.commit()

# Create or update the passwords table with the correct schema
def update_passwords_table():
    c.execute("CREATE TABLE IF NOT EXISTS passwords (title TEXT, username TEXT, password TEXT, url TEXT, notes TEXT, user TEXT)")
    c.execute("PRAGMA table_info(passwords)")
    columns = [info[1] for info in c.fetchall()]
    if "user" not in columns:
        c.execute("ALTER TABLE passwords ADD COLUMN user TEXT")
        conn.commit()

# Create or update the ids table with the correct schema
def update_ids_table():
    c.execute("CREATE TABLE IF NOT EXISTS ids (id INTEGER PRIMARY KEY, file_name TEXT, ipfs_hash TEXT, user TEXT)")
    conn.commit()

# Create or update the ipfs_hashes table to store password files
def update_ipfs_hashes_table():
    c.execute("CREATE TABLE IF NOT EXISTS ipfs_hashes (user TEXT, ipfs_hash TEXT)")
    conn.commit()

update_users_table()
update_passwords_table()
update_ids_table()
update_ipfs_hashes_table()

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.style = ttk.Style()
        self.style.configure('TEntry', padding='10 10 10 10', relief="flat", font=('Arial', 14))
        self.style.configure('TButton', padding='5 5 5 5', font=('Arial', 14))
        self.style.configure('TLabel', font=('Arial', 14))
        self.style.configure('Treeview.Heading', font=('Arial', 14))

        self.current_user = None
        self.file_path = None

        # Initialize IPFS API URL
        self.ipfs_api_url = 'http://127.0.0.1:5001/api/v0'

        self.login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def signup_screen(self):
        self.clear_screen()

        y_position = 0.1
        y_increment = 0.08

        self.signup_label = ttk.Label(self.root, text="Sign Up", background="white")
        self.signup_label.place(relx=0.1, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.signup_username_label = ttk.Label(self.root, text="Enter Username:", background="white")
        self.signup_username_label.place(relx=0.1, rely=y_position, anchor=tk.W)
        self.signup_username_entry = ttk.Entry(self.root, style='TEntry')
        self.signup_username_entry.place(relx=0.3, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.signup_password_label = ttk.Label(self.root, text="Enter Password:", background="white")
        self.signup_password_label.place(relx=0.1, rely=y_position, anchor=tk.W)
        self.signup_password_entry = ttk.Entry(self.root, style='TEntry', show="*")
        self.signup_password_entry.place(relx=0.3, rely=y_position, anchor=tk.W)
        self.signup_password_entry.bind("<KeyRelease>", self.check_password_strength)
        y_position += y_increment

        self.password_strength_label = ttk.Label(self.root, text="Password Strength: ", background="white")
        self.password_strength_label.place(relx=0.1, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.select_file_button = ttk.Button(self.root, text="Select File Location", command=self.select_file_location)
        self.select_file_button.place(relx=0.1, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.signup_button = ttk.Button(self.root, text="Sign Up", command=self.signup)
        self.signup_button.place(relx=0.1, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.switch_to_login_button = ttk.Button(self.root, text="Already have an account? Login", command=self.login_screen)
        self.switch_to_login_button.place(relx=0.1, rely=y_position, anchor=tk.W)
        y_position += y_increment

        self.instructions_label = ttk.Label(self.root, text="Password Instructions: Use at least 8 characters, including upper, lower, digits, and symbols.", background="white")
        self.instructions_label.place(relx=0.1, rely=y_position, anchor=tk.W)

    def select_file_location(self):
        self.file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if self.file_path:
            messagebox.showinfo("Selected File", f"Selected file: {self.file_path}")

    def check_password_strength(self, event):
        password = self.signup_password_entry.get()
        strength = self.password_strength(password)
        self.password_strength_label.config(text=f"Password Strength: {strength}")

    def password_strength(self, password):
        if len(password) < 8:
            return "Too Short"
        if re.search("[a-z]", password) and re.search("[A-Z]", password) and re.search("[0-9]", password) and re.search("[!@#$%^&*(),.?\":{}|<>]", password):
            return "Strong"
        return "Weak"

    def signup(self):
        username = self.signup_username_entry.get()
        password = self.signup_password_entry.get()
        if username and password and self.file_path:
            c.execute("SELECT * FROM users WHERE username=:username", {'username': username})
            if c.fetchone():
                messagebox.showwarning("Warning", "Username already exists")
            else:
                if self.password_strength(password) != "Strong":
                    messagebox.showwarning("Warning", "Password is not strong enough. Follow the instructions to create a strong password.")
                else:
                    encrypted_password = fernet.encrypt(password.encode()).decode()
                    c.execute("INSERT INTO users (username, password, file_path) VALUES (:username, :password, :file_path)",
                              {'username': username, 'password': encrypted_password, 'file_path': self.file_path})
                    conn.commit()
                    messagebox.showinfo("Success", "Sign Up Successful")
                    self.login_screen()
        else:
            messagebox.showwarning("Warning", "Please enter all fields and select a file location")

    def login_screen(self):
        self.clear_screen()

        frame = tk.Frame(self.root, bg='white')
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        self.login_label = ttk.Label(frame, text="Login", background="white")
        self.login_label.grid(row=0, column=0, columnspan=2, pady=10)

        self.login_username_label = ttk.Label(frame, text="Enter Username:", background="white")
        self.login_username_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.login_username_entry = ttk.Entry(frame, style='TEntry')
        self.login_username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        self.login_password_label = ttk.Label(frame, text="Enter Password:", background="white")
        self.login_password_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.login_password_entry = ttk.Entry(frame, style='TEntry', show="*")
        self.login_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        self.login_button = ttk.Button(frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.switch_to_signup_button = ttk.Button(frame, text="Don't have an account? Sign Up", command=self.signup_screen)
        self.switch_to_signup_button.grid(row=4, column=0, columnspan=2, pady=5)

    def login(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()
        if username and password:
            c.execute("SELECT password, file_path FROM users WHERE username=:username", {'username': username})
            result = c.fetchone()
            if result:
                decrypted_password = fernet.decrypt(result[0].encode()).decode()
                if password == decrypted_password:
                    self.current_user = username
                    self.file_path = result[1]
                    messagebox.showinfo("Success", "Login Successful")
                    self.password_manager_screen()
                else:
                    messagebox.showerror("Error", "Incorrect Password")
            else:
                messagebox.showerror("Error", "Username not found")
        else:
            messagebox.showwarning("Warning", "Please enter a username and password")

    def password_manager_screen(self):
        self.clear_screen()

        paned_window = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        # Left panel for forms
        left_frame = ttk.Frame(paned_window, relief=tk.SUNKEN, width=300)
        paned_window.add(left_frame, weight=1)

        self.pm_label = ttk.Label(left_frame, text=f"Password Manager ({self.current_user})")
        self.pm_label.grid(row=0, column=0, columnspan=2, pady=10)

        # Title
        self.title_label = ttk.Label(left_frame, text="Title")
        self.title_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.title_entry = ttk.Entry(left_frame, style='TEntry')
        self.title_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Username
        self.username_label = ttk.Label(left_frame, text="Username")
        self.username_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.username_entry = ttk.Entry(left_frame, style='TEntry')
        self.username_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        # Password
        self.password_label = ttk.Label(left_frame, text="Password")
        self.password_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        self.password_entry = ttk.Entry(left_frame, style='TEntry')
        self.password_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        # URL
        self.url_label = ttk.Label(left_frame, text="URL")
        self.url_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        self.url_entry = ttk.Entry(left_frame, style='TEntry')
        self.url_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)

        # Notes
        self.notes_label = ttk.Label(left_frame, text="Notes")
        self.notes_label.grid(row=5, column=0, padx=5, pady=5, sticky=tk.E)
        self.notes_entry = ttk.Entry(left_frame, style='TEntry')
        self.notes_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)

        # Add Button
        self.add_button = ttk.Button(left_frame, text="Add", command=self.add_password)
        self.add_button.grid(row=6, column=0, columnspan=2, pady=10)

        # Update Button
        self.update_button = ttk.Button(left_frame, text="Update", command=self.prompt_update_password)
        self.update_button.grid(row=7, column=0, columnspan=2, pady=5)

        # Delete Button
        self.delete_button = ttk.Button(left_frame, text="Delete", command=self.delete_password)
        self.delete_button.grid(row=8, column=0, columnspan=2, pady=5)

        # Copy to Clipboard Button
        self.copy_button = ttk.Button(left_frame, text="Copy Password", command=self.copy_password_to_clipboard)
        self.copy_button.grid(row=9, column=0, columnspan=2, pady=5)

        # Load File Button
        self.load_file_button = ttk.Button(left_frame, text="Load Password File", command=self.load_passwords_from_ipfs)
        self.load_file_button.grid(row=10, column=0, columnspan=2, pady=5)

        # Upload ID Button
        self.upload_id_button = ttk.Button(left_frame, text="Upload ID", command=self.upload_id)
        self.upload_id_button.grid(row=11, column=0, columnspan=2, pady=5)

        # View IDs Button
        self.view_ids_button = ttk.Button(left_frame, text="View IDs", command=self.view_ids)
        self.view_ids_button.grid(row=12, column=0, columnspan=2, pady=5)

        # Search bar
        self.search_label = ttk.Label(left_frame, text="Search")
        self.search_label.grid(row=13, column=0, padx=5, pady=5, sticky=tk.E)
        self.search_entry = ttk.Entry(left_frame, style='TEntry')
        self.search_entry.grid(row=13, column=1, padx=5, pady=5, sticky=tk.W)
        self.search_button = ttk.Button(left_frame, text="Search", command=self.search_passwords)
        self.search_button.grid(row=14, column=0, columnspan=2, pady=10)

        # Right panel for treeview
        right_frame = ttk.Frame(paned_window, relief=tk.SUNKEN)
        paned_window.add(right_frame, weight=4)

        # Passwords Treeview
        self.passwords_tree = ttk.Treeview(right_frame, columns=("Title", "Username", "Password", "URL", "Notes"), show="headings")
        self.passwords_tree.heading("Title", text="Title")
        self.passwords_tree.heading("Username", text="Username")
        self.passwords_tree.heading("Password", text="Password")
        self.passwords_tree.heading("URL", text="URL")
        self.passwords_tree.heading("Notes", text="Notes")
        self.passwords_tree.column("Title", width=150, anchor=tk.W)
        self.passwords_tree.column("Username", width=150, anchor=tk.W)
        self.passwords_tree.column("Password", width=150, anchor=tk.W)
        self.passwords_tree.column("URL", width=200, anchor=tk.W)
        self.passwords_tree.column("Notes", width=300, anchor=tk.W)
        self.passwords_tree.pack(fill=tk.BOTH, expand=True)

        self.load_passwords()

    def upload_id(self):
        file_path = filedialog.askopenfilename(title="Select ID File")
        if file_path:
            files = {'file': open(file_path, 'rb')}
            response = requests.post(f'{self.ipfs_api_url}/add', files=files)
            if response.status_code == 200:
                ipfs_hash = response.json()['Hash']
                c.execute("INSERT INTO ids (file_name, ipfs_hash, user) VALUES (?, ?, ?)", 
                          (os.path.basename(file_path), ipfs_hash, self.current_user))
                conn.commit()
                messagebox.showinfo("Success", "ID uploaded to IPFS successfully")
            else:
                messagebox.showerror("Error", "Failed to upload ID to IPFS")

    def view_ids(self):
        ids_window = tk.Toplevel(self.root)
        ids_window.title("Uploaded IDs")

        ids_tree = ttk.Treeview(ids_window, columns=("ID", "File Name", "IPFS Hash"), show="headings")
        ids_tree.heading("ID", text="ID")
        ids_tree.heading("File Name", text="File Name")
        ids_tree.heading("IPFS Hash", text="IPFS Hash")
        ids_tree.column("ID", width=50, anchor=tk.W)
        ids_tree.column("File Name", width=200, anchor=tk.W)
        ids_tree.column("IPFS Hash", width=300, anchor=tk.W)
        ids_tree.pack(fill=tk.BOTH, expand=True)

        c.execute("SELECT id, file_name, ipfs_hash FROM ids WHERE user=?", (self.current_user,))
        for row in c.fetchall():
            ids_tree.insert("", "end", values=row)

        view_button = ttk.Button(ids_window, text="View ID", command=lambda: self.view_selected_id(ids_tree))
        view_button.pack(pady=5)

        delete_button = ttk.Button(ids_window, text="Delete ID", command=lambda: self.delete_selected_id(ids_tree))
        delete_button.pack(pady=5)

    def view_selected_id(self, ids_tree):
        selected_item = ids_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an ID to view")
            return

        ipfs_hash = ids_tree.item(selected_item)['values'][2]
        file_path = filedialog.asksaveasfilename(defaultextension=".id", initialfile=f"{ipfs_hash}.id", title="Save ID File")
        if file_path:
            response = requests.post(f'{self.ipfs_api_url}/get?arg={ipfs_hash}')
            if response.status_code == 200:
                with open(file_path, 'wb') as file:
                    file.write(response.content)
                messagebox.showinfo("Success", f"ID downloaded from IPFS and saved to {file_path}")
            else:
                messagebox.showerror("Error", "Failed to download ID from IPFS")

    def delete_selected_id(self, ids_tree):
        selected_item = ids_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an ID to delete")
            return

        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this ID?")
        if not confirm:
            return

        ipfs_hash = ids_tree.item(selected_item)['values'][2]
        c.execute("DELETE FROM ids WHERE ipfs_hash=?", (ipfs_hash,))
        conn.commit()
        ids_tree.delete(selected_item)

    def load_passwords_from_ipfs(self):
        c.execute("SELECT ipfs_hash FROM ipfs_hashes WHERE user=? ORDER BY ROWID DESC LIMIT 1", (self.current_user,))
        result = c.fetchone()
        if not result:
            messagebox.showwarning("Warning", "No passwords file found on IPFS for this user")
            return

        ipfs_hash = result[0]
        response = requests.post(f'{self.ipfs_api_url}/get?arg={ipfs_hash}')
        if response.status_code == 200:
            encrypted_data = response.content
            try:
                decrypted_data = fernet.decrypt(encrypted_data).decode()
                passwords = json.loads(decrypted_data)
                self.passwords_tree.delete(*self.passwords_tree.get_children())
                for password in passwords:
                    decrypted_password = fernet.decrypt(password['password'].encode()).decode()
                    self.passwords_tree.insert("", "end", values=(password['title'], password['username'], decrypted_password, password['url'], password['notes']))
                messagebox.showinfo("Success", "Passwords loaded from IPFS successfully")
            except Exception as e:
                logging.error(f"Error decrypting data: {e}")
                messagebox.showerror("Error", "Could not decrypt the file. Please check the encryption key.")
        else:
            messagebox.showerror("Error", "Failed to retrieve passwords from IPFS")

    def add_password(self):
        title = self.title_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        notes = self.notes_entry.get()

        if title and username and password:
            encrypted_password = fernet.encrypt(password.encode()).decode()
            password_entry = {
                'title': title,
                'username': username,
                'password': encrypted_password,
                'url': url,
                'notes': notes
            }
            passwords = self.load_passwords_from_file()
            passwords.append(password_entry)
            self.save_passwords_to_file(passwords)
            self.upload_passwords_to_ipfs(passwords)
            self.load_passwords()
            self.clear_entries()
        else:
            messagebox.showwarning("Warning", "Please fill out all required fields")

    def load_passwords(self):
        self.passwords_tree.delete(*self.passwords_tree.get_children())
        passwords = self.load_passwords_from_file()
        for password in passwords:
            decrypted_password = fernet.decrypt(password['password'].encode()).decode()
            self.passwords_tree.insert("", "end", values=(password['title'], password['username'], decrypted_password, password['url'], password['notes']))

    def load_passwords_from_file(self):
        if not self.file_path or not os.path.exists(self.file_path):
            return []
        with open(self.file_path, 'rb') as file:
            encrypted_data = file.read()
            try:
                decrypted_data = fernet.decrypt(encrypted_data).decode()
                passwords = json.loads(decrypted_data)
            except Exception as e:
                logging.error(f"Error decrypting data: {e}")
                messagebox.showerror("Error", "Could not decrypt the file. Please check the encryption key.")
                return []
        return passwords

    def save_passwords_to_file(self, passwords):
        if not self.file_path:
            return
        encrypted_data = fernet.encrypt(json.dumps(passwords).encode())
        with open(self.file_path, 'wb') as file:
            file.write(encrypted_data)

    def upload_passwords_to_ipfs(self, passwords):
        temp_file_path = "temp_passwords.json"
        with open(temp_file_path, 'w') as file:
            file.write(fernet.encrypt(json.dumps(passwords).encode()).decode())

        files = {'file': open(temp_file_path, 'rb')}
        response = requests.post(f'{self.ipfs_api_url}/add', files=files)
        if response.status_code == 200:
            ipfs_hash = response.json()['Hash']
            logging.info(f"Uploaded passwords file to IPFS with hash: {ipfs_hash}")

            c.execute("INSERT INTO ipfs_hashes (user, ipfs_hash) VALUES (?, ?)", (self.current_user, ipfs_hash))
            conn.commit()
            
            messagebox.showinfo("Success", f"Passwords uploaded to IPFS successfully. IPFS Hash: {ipfs_hash}")
        else:
            logging.error("Failed to upload file to IPFS")
            messagebox.showerror("Error", "Failed to upload file to IPFS")

        os.remove(temp_file_path)

    def search_passwords(self):
        query = self.search_entry.get().lower()
        if not query:
            self.load_passwords()
            return

        filtered_passwords = []
        passwords = self.load_passwords_from_file()
        for password in passwords:
            if query in password['title'].lower() or query in password['username'].lower() or query in password['url'].lower() or query in password['notes'].lower():
                decrypted_password = fernet.decrypt(password['password'].encode()).decode()
                filtered_passwords.append((password['title'], password['username'], decrypted_password, password['url'], password['notes']))

        self.passwords_tree.delete(*self.passwords_tree.get_children())
        for password in filtered_passwords:
            self.passwords_tree.insert("", "end", values=password)

    def prompt_update_password(self):
        selected_item = self.passwords_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password to update")
            return

        self.current_item_id = self.passwords_tree.item(selected_item)['values'][0]

        self.update_password_window = tk.Toplevel(self.root)
        self.update_password_window.title("Update Password")

        self.new_password_label = ttk.Label(self.update_password_window, text="Enter New Password:")
        self.new_password_label.pack(pady=10)
        self.new_password_entry = ttk.Entry(self.update_password_window, style='TEntry', show='*')
        self.new_password_entry.pack(pady=10)

        self.reenter_password_label = ttk.Label(self.update_password_window, text="Re-enter New Password:")
        self.reenter_password_label.pack(pady=10)
        self.reenter_password_entry = ttk.Entry(self.update_password_window, style='TEntry', show='*')
        self.reenter_password_entry.pack(pady=10)

        self.confirm_button = ttk.Button(self.update_password_window, text="Confirm", command=self.confirm_update_password)
        self.confirm_button.pack(pady=10)

    def confirm_update_password(self):
        new_password = self.new_password_entry.get()
        reenter_password = self.reenter_password_entry.get()

        if new_password and reenter_password:
            if new_password == reenter_password:
                self.update_password(new_password)
                self.update_password_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
        else:
            messagebox.showwarning("Warning", "Please enter and re-enter the new password")

    def update_password(self, new_password):
        if self.current_item_id is None:
            messagebox.showwarning("Warning", "No password selected for update")
            return

        passwords = self.load_passwords_from_file()
        password_entry = passwords[self.current_item_id]

        encrypted_password = fernet.encrypt(new_password.encode()).decode()
        password_entry['password'] = encrypted_password

        self.save_passwords_to_file(passwords)
        self.upload_passwords_to_ipfs(passwords)
        self.load_passwords()
        self.clear_entries()
        self.current_item_id = None  # Reset current item ID after update

    def delete_password(self):
        selected_item = self.passwords_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password to delete")
            return

        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?")
        if not confirm:
            return

        try:
            self.current_item_id = self.passwords_tree.item(selected_item)['values'][0]
            passwords = self.load_passwords_from_file()
            passwords.pop(self.current_item_id)
            self.save_passwords_to_file(passwords)
            self.upload_passwords_to_ipfs(passwords)
            self.load_passwords()
            self.clear_entries()
        except IndexError:
            messagebox.showwarning("Warning", "Please select a password to delete")

    def copy_password_to_clipboard(self):
        selected_item = self.passwords_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select a password to copy")
            return

        try:
            self.current_item_id = self.passwords_tree.item(selected_item)['values'][0]
            passwords = self.load_passwords_from_file()
            password = passwords[self.current_item_id]

            decrypted_password = fernet.decrypt(password['password'].encode()).decode()
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_password)
            self.root.update()  # Keeps the clipboard updated
            messagebox.showinfo("Copied", "Password copied to clipboard")
        except IndexError:
            messagebox.showwarning("Warning", "Please select a password to copy")

    def clear_entries(self):
        self.title_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.url_entry.delete(0, tk.END)
        self.notes_entry.delete(0, tk.END)
        self.current_item_id = None  # Reset current item ID on clear

# Initialize Tkinter
root = tk.Tk()
app = PasswordManagerApp(root)
root.mainloop()

# Close the connection
conn.close()
