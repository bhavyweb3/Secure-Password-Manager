# 🔐 Secure Password Manager

A simple and secure **Password Manager** built using Python. It provides a graphical interface to securely store, manage, generate, and retrieve passwords.

## 📌 Features

* 🔑 Master password protection
* 🔒 AES-256-GCM encryption for stored passwords
* 🗄️ SQLite database for storing password information
* 🎲 Secure password generator
* 💪 Password strength checker
* 🚨 Password breach checking
* 🔍 Search saved passwords
* 👁️ Show/Hide password option
* 📋 Copy password to clipboard
* ⏱️ Automatic session lock
* 📤 Export password data to JSON
* 🗑️ Add, retrieve, update, and delete passwords

## 🛠️ Technologies Used

* **Python**
* **Tkinter** – Graphical User Interface
* **SQLite3** – Database
* **Cryptography** – Password encryption
* **AES-256-GCM** – Encryption method
* **PBKDF2-HMAC-SHA256** – Key derivation
* **Base64** – Secure data encoding

## 📂 Project Structure

```text
Secure-Password-Manager/
│
├── main.py
├── passwords_secure.db
└── README.md
```

## ⚙️ Requirements

Make sure Python is installed on your computer.

Install the required library:

```bash
pip install cryptography
```

Tkinter and SQLite3 are included with most Python installations.

## ▶️ How to Run

1. Clone the repository:

```bash
https://github.com/bhavyweb3/Secure-Password-Manager.git
```

2. Open the project folder:

```bash
cd YOUR-REPOSITORY
```

3. Install the required package:

```bash
pip install cryptography
```

4. Run the application:

```bash
python main.py
```

## 🔐 How It Works

The application uses a **master password** to protect access to stored passwords.

Passwords are encrypted before being stored in the SQLite database. The project uses **AES-256-GCM encryption** and **PBKDF2-HMAC-SHA256** for secure key generation.

The application also provides a secure password generator and checks password strength.

## 🗄️ Database

The application uses a local SQLite database:

```text
passwords_secure.db
```

The database stores information such as:

* Service name
* Username
* Encrypted password
* Salt
* Initialization Vector (IV)
* Authentication tag
* Created and updated time

Passwords are not stored as plain text.

## 🔑 Security Features

* AES-256-GCM encryption
* Secure random password generation
* Strong master password validation
* PBKDF2 key derivation
* Automatic session timeout
* Clipboard auto-clear
* Password strength analysis

## 🚨 Breach Monitoring

The project includes a password breach checking feature. The current implementation uses a built-in list and simulated breach checking for demonstration purposes.

## 👨‍💻 Author

**Bhavya Goel**

B.Tech Computer Science – Blockchain

## 📄 License

This project is created for **educational and academic purposes**.

## ScreenShots
<img width="1910" height="1016" alt="image" src="https://github.com/user-attachments/assets/356ef5d8-1271-4830-b498-7668e689084d" />
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/8ec99d55-0dad-41b4-85e3-293735a7dfa5" />
<img width="450" height="400" alt="image" src="https://github.com/user-attachments/assets/4ef14ddc-f746-46bb-9a40-c18afe884c1b" />
<img width="300" height="200" alt="image" src="https://github.com/user-attachments/assets/3bf9e95a-05e1-44ad-b5a7-517c12bfbbae" />



