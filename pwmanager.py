import sys
from cryptography.fernet import Fernet
import sqlite3
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtGui import QClipboard


class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.create_database()
        
        self.load_key()

    def init_ui(self):
        self.setGeometry(200, 200, 400, 200)
        self.setWindowTitle('Password Manager')
        layout = QVBoxLayout()

        self.username_label = QLabel('Username:')
        layout.addWidget(self.username_label)

        self.username_input = QLineEdit()
        layout.addWidget(self.username_input)

        self.password_label = QLabel('Password:')
        layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        save_button = QPushButton('Save Password')
        save_button.clicked.connect(self.save_password)
        layout.addWidget(save_button)

        get_button = QPushButton('Get Password')
        get_button.clicked.connect(self.get_password)
        layout.addWidget(get_button)

        self.setLayout(layout)
        
    def save_key(self):
        with open('key.key', 'wb') as key_file:
            key_file.write(self.key)

    def load_key(self):
        try:
            with open('key.key', 'rb') as key_file:
                self.key = key_file.read()
        except FileNotFoundError:
            self.key = Fernet.generate_key()
            self.save_key()

    def create_database(self):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute('''CREATE TABLE IF NOT EXISTS passwords
                     (username TEXT PRIMARY KEY, password TEXT)''')

        conn.commit()
        conn.close()

    def check_username_exists(self, username):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute("SELECT * FROM passwords WHERE username=?", (username,))
        result = c.fetchone()

        conn.close()

        return result is not None

    def encode_password(self, password):
        cipher_suite = Fernet(self.key)
        encoded_password = cipher_suite.encrypt(password.encode())
        return encoded_password.decode()

    def store_password(self, username, encoded_password):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute("INSERT INTO passwords VALUES (?, ?)", (username, encoded_password))

        conn.commit()
        conn.close()

    def retrieve_password(self, username):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute("SELECT password FROM passwords WHERE username=?", (username,))
        result = c.fetchone()

        conn.close()

        if result:
            return result[0]
        QMessageBox.warning(self, 'Username Not Found', 'Username does not exist in the database.')
        return None

    def decode_password(self, encoded_password):
        cipher_suite = Fernet(self.key)
        decoded_password = cipher_suite.decrypt(encoded_password.encode())
        return decoded_password.decode()

    def save_password(self):
        username = self.username_input.text()
        password = self.password_input.text()
        # Check if the username already exists in the database
        if self.check_username_exists(username):
            QMessageBox.warning(self, 'Username Exists', 'Username already exists. Please choose a different username.')
            return

        encoded_password = self.encode_password(password)
        self.store_password(username, encoded_password)

        QMessageBox.information(self, 'Password Saved', 'Password has been saved successfully.')

    def get_password(self):
        username = self.username_input.text()

        # Retrieve the encoded password from the database
        encoded_password = self.retrieve_password(username)

        if encoded_password:
            # Decode the password
            password = self.decode_password(encoded_password)
            # print(password)
            clipboard = QApplication.clipboard()
            clipboard.setText(password, QClipboard.Clipboard)
            clipboard.setText(password, QClipboard.Selection)

            QMessageBox.information(self, 'Password Copied', 'Password has been copied to the clipboard.')
        else:
            QMessageBox.warning(self, 'Password Not Found', 'Password does not exist for the given username.')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec_())
