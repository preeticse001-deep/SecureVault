import sys
import os
import threading
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QLabel, QLineEdit, QPushButton, QCheckBox, 
    QTextEdit, QFileDialog, QMessageBox, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont
from crypto_backend import FileEncryptor

class WorkerSignals(QObject):
    log_signal = pyqtSignal(str)
    toggle_ui_signal = pyqtSignal(bool)
    clear_inputs_signal = pyqtSignal(str)
    overwrite_request = pyqtSignal(str, object) 

class SecureVaultPyQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.encryptor = FileEncryptor()
        self.signals = WorkerSignals()
        
        self.failed_attempts = {}
        
        self.signals.log_signal.connect(self.log)
        self.signals.toggle_ui_signal.connect(self.toggle_ui)
        self.signals.clear_inputs_signal.connect(self.clear_inputs)
        self.signals.overwrite_request.connect(self.prompt_overwrite_sync)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SecureVault - Enterprise PKI Edition")
        self.setFixedSize(650, 780)
        self.apply_theme()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Segoe UI", 10))
        main_layout.addWidget(self.tabs)

        # Initialize all three tabs
        self.init_encrypt_tab()
        self.init_decrypt_tab()
        self.init_rsa_tab()

        console_label = QLabel("Activity Log Console:")
        console_label.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        main_layout.addWidget(console_label)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setFixedHeight(140)
        main_layout.addWidget(self.console)

        self.center_window()
        self.log("SecureVault PKI Engine initialized. System ready.")

    def apply_theme(self):
        is_dark = True
        try:
            import winreg
            registry = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            key = winreg.OpenKey(registry, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            is_dark = value == 0
        except Exception:
            pass

        if is_dark:
            self.setStyleSheet("""
                QMainWindow { background-color: #121214; }
                QTabWidget::pane { border: 1px solid #27272a; border-radius: 8px; background-color: #1c1c1f; }
                QTabBar::tab { background: #121214; color: #a1a1aa; padding: 10px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
                QTabBar::tab:selected { background: #1c1c1f; color: #ffffff; font-weight: bold; }
                QLabel { color: #e4e4e7; font-family: 'Segoe UI'; }
                QLineEdit { background-color: #27272a; color: #ffffff; border: 1px solid #3f3f46; border-radius: 5px; padding: 6px; font-size: 13px; }
                QLineEdit:focus { border: 1px solid #3b82f6; }
                QPushButton { background-color: #2563eb; color: #ffffff; border: none; border-radius: 5px; padding: 8px 15px; font-weight: bold; font-family: 'Segoe UI'; }
                QPushButton:hover { background-color: #1d4ed8; }
                QPushButton:disabled { background-color: #3f3f46; color: #a1a1aa; }
                QCheckBox { color: #e4e4e7; font-family: 'Segoe UI'; }
                QTextEdit { background-color: #09090b; color: #4ade80; border: 1px solid #27272a; border-radius: 6px; padding: 5px; }
                QFrame[frameShape="4"] { color: #3f3f46; } /* HLine color */
            """)
        else:
            self.setStyleSheet("""
                QMainWindow { background-color: #f4f4f5; }
                QTabWidget::pane { border: 1px solid #e4e4e7; border-radius: 8px; background-color: #ffffff; }
                QTabBar::tab { background: #e4e4e7; color: #71717a; padding: 10px 20px; border-top-left-radius: 6px; border-top-right-radius: 6px; }
                QTabBar::tab:selected { background: #ffffff; color: #09090b; font-weight: bold; }
                QLabel { color: #09090b; font-family: 'Segoe UI'; }
                QLineEdit { background-color: #ffffff; color: #09090b; border: 1px solid #d4d4d8; border-radius: 5px; padding: 6px; font-size: 13px; }
                QLineEdit:focus { border: 1px solid #2563eb; }
                QPushButton { background-color: #2563eb; color: #ffffff; border: none; border-radius: 5px; padding: 8px 15px; font-weight: bold; font-family: 'Segoe UI'; }
                QPushButton:hover { background-color: #1d4ed8; }
                QPushButton:disabled { background-color: #e4e4e7; color: #a1a1aa; }
                QCheckBox { color: #09090b; font-family: 'Segoe UI'; }
                QTextEdit { background-color: #fafafa; color: #16a34a; border: 1px solid #e4e4e7; border-radius: 6px; padding: 5px; }
                QFrame[frameShape="4"] { color: #e4e4e7; } /* HLine color */
            """)

    def center_window(self):
        frame_gm = self.frameGeometry()
        screen_obj = QApplication.primaryScreen()
        if screen_obj is not None:
            screen_center = screen_obj.geometry().center()
            frame_gm.moveCenter(screen_center)
            self.move(frame_gm.topLeft())
        else:
            self.move(100, 100)

    # --- TAB 1: LOCAL ENCRYPT ---
    def init_encrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        layout.addWidget(QLabel("Target File or Folder Path:"))
        target_h_layout = QHBoxLayout()
        self.enc_target_input = QLineEdit()
        target_h_layout.addWidget(self.enc_target_input)
        
        btn_file = QPushButton("File")
        btn_file.clicked.connect(lambda *args: self.browse_path(self.enc_target_input, "file"))
        btn_folder = QPushButton("Folder")
        btn_folder.clicked.connect(lambda *args: self.browse_path(self.enc_target_input, "folder"))
        target_h_layout.addWidget(btn_file)
        target_h_layout.addWidget(btn_folder)
        layout.addLayout(target_h_layout)

        layout.addWidget(QLabel("Custom Destination (Optional):"))
        out_h_layout = QHBoxLayout()
        self.enc_output_input = QLineEdit()
        self.enc_output_input.setPlaceholderText("Auto-generates next to target if left blank...")
        out_h_layout.addWidget(self.enc_output_input)
        
        btn_out_browse = QPushButton("Save As")
        btn_out_browse.clicked.connect(lambda *args: self.browse_save_path(self.enc_output_input))
        out_h_layout.addWidget(btn_out_browse)
        layout.addLayout(out_h_layout)

        layout.addWidget(QLabel("Master Password:"))
        self.enc_pass_input = QLineEdit()
        self.enc_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.enc_pass_input)

        layout.addWidget(QLabel("Confirm Password:"))
        self.enc_conf_input = QLineEdit()
        self.enc_conf_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.enc_conf_input)

        self.shred_checkbox = QCheckBox("Securely shred original item after system lock")
        layout.addWidget(self.shred_checkbox)

        layout.addStretch()

        self.btn_lock = QPushButton("LOCAL LOCK")
        self.btn_lock.setFixedHeight(45)
        self.btn_lock.clicked.connect(self.start_encryption_thread)
        layout.addWidget(self.btn_lock)

        self.tabs.addTab(tab, "Local Encrypt")

    # --- TAB 2: LOCAL DECRYPT ---
    def init_decrypt_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        layout.addWidget(QLabel("Encrypted Archive Target (.enc / .zip.enc):"))
        target_h_layout = QHBoxLayout()
        self.dec_target_input = QLineEdit()
        target_h_layout.addWidget(self.dec_target_input)
        
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(lambda *args: self.browse_path(self.dec_target_input, "file"))
        target_h_layout.addWidget(btn_browse)
        layout.addLayout(target_h_layout)

        layout.addWidget(QLabel("Custom Destination (Optional):"))
        out_h_layout = QHBoxLayout()
        self.dec_output_input = QLineEdit()
        self.dec_output_input.setPlaceholderText("Auto-generates next to target if left blank...")
        out_h_layout.addWidget(self.dec_output_input)
        
        btn_out_browse = QPushButton("Save As")
        btn_out_browse.clicked.connect(lambda *args: self.browse_save_path(self.dec_output_input))
        out_h_layout.addWidget(btn_out_browse)
        layout.addLayout(out_h_layout)

        layout.addWidget(QLabel("Master Password Verification:"))
        self.dec_pass_input = QLineEdit()
        self.dec_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.dec_pass_input)

        layout.addStretch()

        self.btn_unlock = QPushButton("LOCAL UNLOCK")
        self.btn_unlock.setFixedHeight(45)
        self.btn_unlock.setStyleSheet("QPushButton { background-color: #16a34a; } QPushButton:hover { background-color: #15803d; }")
        self.btn_unlock.clicked.connect(self.start_decryption_thread)
        layout.addWidget(self.btn_unlock)

        self.tabs.addTab(tab, "Local Decrypt")

    # --- TAB 3: ASYMMETRIC (RSA) ---
    def init_rsa_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(20, 10, 20, 10)
        layout.setSpacing(10)

        # 1. Key Generation Section
        lbl_keygen = QLabel("1. Identity Management")
        lbl_keygen.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_keygen)

        self.btn_keygen = QPushButton("Generate New RSA-4096 Keypair")
        self.btn_keygen.setStyleSheet("QPushButton { background-color: #6366f1; } QPushButton:hover { background-color: #4f46e5; }")
        self.btn_keygen.clicked.connect(self.start_rsa_keygen_thread)
        layout.addWidget(self.btn_keygen)

        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line1)

        # 2. Encrypt for Sharing
        lbl_share = QLabel("2. Package for Sharing (Requires Recipient's Public Key)")
        lbl_share.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_share)

        layout.addWidget(QLabel("Target File:"))
        h_rsa_enc_target = QHBoxLayout()
        self.rsa_enc_target = QLineEdit()
        h_rsa_enc_target.addWidget(self.rsa_enc_target)
        btn_rsa_enc_browse = QPushButton("Browse")
        btn_rsa_enc_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_enc_target, "file"))
        h_rsa_enc_target.addWidget(btn_rsa_enc_browse)
        layout.addLayout(h_rsa_enc_target)

        layout.addWidget(QLabel("Recipient's Public Key (.pem):"))
        h_rsa_pub = QHBoxLayout()
        self.rsa_pub_key = QLineEdit()
        h_rsa_pub.addWidget(self.rsa_pub_key)
        btn_rsa_pub_browse = QPushButton("Browse")
        btn_rsa_pub_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_pub_key, "file", filter="PEM Files (*.pem)"))
        h_rsa_pub.addWidget(btn_rsa_pub_browse)
        layout.addLayout(h_rsa_pub)

        self.btn_rsa_enc = QPushButton("SECURE PACKAGE")
        self.btn_rsa_enc.clicked.connect(self.start_rsa_encrypt_thread)
        layout.addWidget(self.btn_rsa_enc)

        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(line2)

        # 3. Decrypt Received File
        lbl_receive = QLabel("3. Unlock Received File (Requires Your Private Key)")
        lbl_receive.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        layout.addWidget(lbl_receive)

        layout.addWidget(QLabel("Encrypted Package (.rsa.enc):"))
        h_rsa_dec_target = QHBoxLayout()
        self.rsa_dec_target = QLineEdit()
        h_rsa_dec_target.addWidget(self.rsa_dec_target)
        btn_rsa_dec_browse = QPushButton("Browse")
        btn_rsa_dec_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_dec_target, "file"))
        h_rsa_dec_target.addWidget(btn_rsa_dec_browse)
        layout.addLayout(h_rsa_dec_target)

        layout.addWidget(QLabel("Your Private Key (.pem):"))
        h_rsa_priv = QHBoxLayout()
        self.rsa_priv_key = QLineEdit()
        h_rsa_priv.addWidget(self.rsa_priv_key)
        btn_rsa_priv_browse = QPushButton("Browse")
        btn_rsa_priv_browse.clicked.connect(lambda *args: self.browse_path(self.rsa_priv_key, "file", filter="PEM Files (*.pem)"))
        h_rsa_priv.addWidget(btn_rsa_priv_browse)
        layout.addLayout(h_rsa_priv)

        self.btn_rsa_dec = QPushButton("UNLOCK PACKAGE")
        self.btn_rsa_dec.setStyleSheet("QPushButton { background-color: #16a34a; } QPushButton:hover { background-color: #15803d; }")
        self.btn_rsa_dec.clicked.connect(self.start_rsa_decrypt_thread)
        layout.addWidget(self.btn_rsa_dec)

        layout.addStretch()
        self.tabs.addTab(tab, "Asymmetric Sharing")

    # --- UI UTILITIES ---
    def browse_save_path(self, line_edit, filter=""):
        options = QFileDialog.Option.DontUseNativeDialog
        path, _ = QFileDialog.getSaveFileName(self, "Select Destination Path", filter=filter, options=options)
        if path:
            line_edit.setText(os.path.normpath(path))

    def browse_path(self, line_edit, mode, filter=""):
        options = QFileDialog.Option.DontUseNativeDialog
        if mode == "file":
            path, _ = QFileDialog.getOpenFileName(self, "Select File", filter=filter, options=options)
        else:
            path = QFileDialog.getExistingDirectory(self, "Select Directory", options=options)
            
        if path:
            line_edit.setText(os.path.normpath(path))

    def log(self, text):
        import html
        safe_text = html.escape(text)
        
        if "[CRITICAL]" in safe_text:
            formatted_text = f'<span style="color: #ef4444; font-weight: bold;">&gt; {safe_text}</span>'
        elif "[-]" in safe_text or "Error" in safe_text or "Aborted" in safe_text or "Failed" in safe_text:
            formatted_text = f'<span style="color: #ef4444;">&gt; {safe_text}</span>'
        elif "[!]" in safe_text or "Warning" in safe_text or "Check" in safe_text:
            formatted_text = f'<span style="color: #f59e0b;">&gt; {safe_text}</span>'
        elif "[+]" in safe_text:
            formatted_text = f'<span style="color: #3b82f6;">&gt; {safe_text}</span>'
        else:
            formatted_text = f"&gt; {safe_text}"
            
        self.console.append(formatted_text)

    def toggle_ui(self, enable):
        # Local Buttons
        self.btn_lock.setEnabled(enable)
        self.btn_unlock.setEnabled(enable)
        # RSA Buttons
        self.btn_keygen.setEnabled(enable)
        self.btn_rsa_enc.setEnabled(enable)
        self.btn_rsa_dec.setEnabled(enable)

    def clear_inputs(self, engine):
        if engine == "enc":
            self.enc_target_input.clear()
            self.enc_output_input.clear()
            self.enc_pass_input.clear()
            self.enc_conf_input.clear()
        elif engine == "dec":
            self.dec_target_input.clear()
            self.dec_output_input.clear()
            self.dec_pass_input.clear()
        elif engine == "rsa_enc":
            self.rsa_enc_target.clear()
            self.rsa_pub_key.clear()
        elif engine == "rsa_dec":
            self.rsa_dec_target.clear()
            self.rsa_priv_key.clear()

    def prompt_overwrite_sync(self, path, container_list):
        reply = QMessageBox.question(
            self, 'Overwrite System Check',
            f"The target item '{os.path.basename(path)}' already exists.\n\nOverwrite it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
        )
        container_list.append(reply == QMessageBox.StandardButton.Yes)

    # --- TAB 1 THREADS (LOCAL ENCRYPT) ---
    def start_encryption_thread(self):
        target = self.enc_target_input.text()
        custom_out = self.enc_output_input.text().strip() or None
        pwd = self.enc_pass_input.text()
        conf = self.enc_conf_input.text()
        shred = self.shred_checkbox.isChecked()

        if not target or not pwd:
            self.log("[-] Error: Missing target configuration paths or access tokens.")
            return
        if pwd != conf:
            self.log("[-] Error: Key verification validation mismatch.")
            return
        if not os.path.exists(target):
            self.log("[-] Error: Network/Local target path resolution failure.")
            return

        expected_out = custom_out if custom_out else (f"{target}.zip.enc" if os.path.isdir(target) else f"{target}.enc")
        if os.path.exists(expected_out):
            reply = QMessageBox.question(
                self, 'Overwrite Check', f"Archive '{os.path.basename(expected_out)}' already exists.\n\nOverwrite?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.log("[-] Aborted to protect existing archive.")
                return

        self.toggle_ui(False)
        threading.Thread(target=self._exec_encryption, args=(target, pwd, shred, custom_out), daemon=True).start()

    def _exec_encryption(self, target, pwd, shred, custom_out):
        try:
            self.signals.log_signal.emit(f"Initializing encryption matrix for: {os.path.basename(target)}")
            if os.path.isdir(target):
                out = self.encryptor.encrypt_directory(target, pwd, output_path=custom_out)
            else:
                out = self.encryptor.encrypt_file(target, pwd, output_path=custom_out)
            
            self.signals.log_signal.emit(f"[+] Output locked to disk: {os.path.basename(out)}")
            
            if shred:
                self.signals.log_signal.emit("[*] Commencing anti-forensic wipe...")
                self.encryptor.secure_delete(target)
                self.signals.log_signal.emit("[+] Original data blocks completely wiped.")
                
            self.signals.clear_inputs_signal.emit("enc")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Execution Aborted: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    # --- TAB 2 THREADS (LOCAL DECRYPT) ---
    def start_decryption_thread(self):
        target = self.dec_target_input.text()
        custom_out = self.dec_output_input.text().strip() or None
        pwd = self.dec_pass_input.text()

        if not target or not pwd:
            self.log("[-] Error: Target payload and verification tokens required.")
            return
        if not os.path.exists(target):
            self.log("[-] Error: Target resolved to null.")
            return

        self.toggle_ui(False)
        threading.Thread(target=self._exec_decryption, args=(target, pwd, custom_out), daemon=True).start()

    def _exec_decryption(self, target, pwd, custom_out):
        try:
            self.signals.log_signal.emit(f"Passing crypt-stream parameters for: {os.path.basename(target)}")
            
            def thread_safe_overwrite_check(out_path):
                result_container = []
                self.signals.overwrite_request.emit(out_path, result_container)
                while not result_container:
                    time.sleep(0.05)
                return result_container[0]

            if target.endswith('.zip.enc'):
                out = self.encryptor.decrypt_directory(target, pwd, output_path=custom_out, overwrite_callback=thread_safe_overwrite_check)
            else:
                out = self.encryptor.decrypt_file(target, pwd, output_path=custom_out, overwrite_callback=thread_safe_overwrite_check)
                
            self.signals.log_signal.emit(f"[+] Decrypted sequence output success: {os.path.basename(out)}")
            
            if target in self.failed_attempts:
                del self.failed_attempts[target]
                
            self.signals.clear_inputs_signal.emit("dec")
            
        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except ValueError as ve:
            if "signature verification failed" in str(ve).lower():
                attempts = self.failed_attempts.get(target, 0) + 1
                self.failed_attempts[target] = attempts
                
                remaining = 5 - attempts
                if remaining > 0:
                    self.signals.log_signal.emit(f"[-] Incorrect Password. {remaining} attempts remaining before self-destruct.")
                else:
                    self.signals.log_signal.emit(f"[CRITICAL] 5 consecutive failed attempts. Triggering Dead Man's Switch...")
                    try:
                        self.encryptor.secure_delete(target)
                        self.signals.log_signal.emit(f"[!] Target '{os.path.basename(target)}' securely shredded from disk.")
                    except Exception as e:
                        self.signals.log_signal.emit(f"[-] Shredder execution failed: {e}")
                    del self.failed_attempts[target]
            else:
                self.signals.log_signal.emit(f"[-] Authentication Failure: {ve}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Critical Error: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    # --- TAB 3 THREADS (ASYMMETRIC RSA) ---
    def start_rsa_keygen_thread(self):
        options = QFileDialog.Option.DontUseNativeDialog
        save_dir = QFileDialog.getExistingDirectory(self, "Select Folder to Save Keys", options=options)
        if not save_dir:
            return
            
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_keygen, args=(save_dir,), daemon=True).start()
        
    def _exec_rsa_keygen(self, save_dir):
        try:
            self.signals.log_signal.emit("[*] Generating 4096-bit RSA Keypair... (This may take a moment)")
            priv_path = os.path.join(save_dir, "my_private_key.pem")
            pub_path = os.path.join(save_dir, "my_public_key.pem")
            
            self.encryptor.generate_rsa_keypair(priv_path, pub_path)
            
            self.signals.log_signal.emit(f"[+] Success! Keys saved to: {save_dir}")
            self.signals.log_signal.emit("[!] WARNING: Never share your PRIVATE key with anyone.")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Keygen Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    def start_rsa_encrypt_thread(self):
        target = self.rsa_enc_target.text()
        pub_key = self.rsa_pub_key.text()
        
        if not target or not pub_key:
            self.log("[-] Error: Missing Target File or Recipient's Public Key.")
            return
            
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_encrypt, args=(target, pub_key), daemon=True).start()
        
    def _exec_rsa_encrypt(self, target, pub_key):
        try:
            self.signals.log_signal.emit(f"[*] Packaging payload via Hybrid RSA envelope: {os.path.basename(target)}")
            out = self.encryptor.rsa_encrypt_file(target, pub_key)
            self.signals.log_signal.emit(f"[+] Secure package generated: {os.path.basename(out)}")
            self.signals.clear_inputs_signal.emit("rsa_enc")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Packaging Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

    def start_rsa_decrypt_thread(self):
        target = self.rsa_dec_target.text()
        priv_key = self.rsa_priv_key.text()
        
        if not target or not priv_key:
            self.log("[-] Error: Missing Encrypted Package or your Private Key.")
            return
            
        self.toggle_ui(False)
        threading.Thread(target=self._exec_rsa_decrypt, args=(target, priv_key), daemon=True).start()
        
    def _exec_rsa_decrypt(self, target, priv_key):
        try:
            self.signals.log_signal.emit(f"[*] Unlocking envelope with your Private Key: {os.path.basename(target)}")
            
            def thread_safe_overwrite_check(out_path):
                result_container = []
                self.signals.overwrite_request.emit(out_path, result_container)
                while not result_container:
                    time.sleep(0.05)
                return result_container[0]
                
            out = self.encryptor.rsa_decrypt_file(target, priv_key, overwrite_callback=thread_safe_overwrite_check)
            self.signals.log_signal.emit(f"[+] Package successfully unlocked: {os.path.basename(out)}")
            self.signals.clear_inputs_signal.emit("rsa_dec")
        except InterruptedError as ie:
            self.signals.log_signal.emit(f"[-] Operation Aborted: {str(ie)}")
        except ValueError as ve:
            self.signals.log_signal.emit(f"[-] Access Denied: {ve}")
        except Exception as e:
            self.signals.log_signal.emit(f"[-] Decryption Failed: {str(e)}")
        finally:
            self.signals.toggle_ui_signal.emit(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecureVaultPyQt()
    window.show()
    sys.exit(app.exec())
