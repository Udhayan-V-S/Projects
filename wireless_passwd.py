# from PyQt6.QtWidgets import QWidget, QTableWidgetItem, QGroupBox, QLabel, QLineEdit
# from PyQt6.QtCore import QTimer
# from gui import create_layout, create_button, create_table, save_to_file, save_to_txt
# import subprocess
# import re
# import os
# import locale

# # Set locale to ensure UTF-8 support and fix Gtk warning
# try:
#     locale.setlocale(locale.LC_ALL, "en_US.UTF-8")  # Use an available UTF-8 locale
# except locale.Error:
#     try:
#         locale.setlocale(locale.LC_ALL, "")  # Fallback to system default if en_US.UTF-8 isn’t available
#     except locale.Error:
#         pass  # If all fails, proceed with default 'C' locale
# os.environ["LC_ALL"] = "en_US.UTF-8"  # Also set environment variable for subprocesses
# os.environ["LANG"] = "en_US.UTF-8"    # Ensure consistency

# class WirelessPasswordTab(QWidget):
#     def __init__(self, parent=None):
#         super().__init__()
#         self.parent = parent
#         self.total_networks = 0
#         self.networks = []
#         self.init_ui()
#         self.timer = QTimer(self)
#         self.timer.timeout.connect(self.refresh_table)

#     def init_ui(self):
#         self.desc_label = QLabel("Find the wireless network password of the device which you have previously connected in this device.")
#         self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")

#         self.status_label = QLabel(f"Total Networks Found: {self.total_networks}")
#         self.status_label.setStyleSheet("padding: 5px; font-size: 12px;")

#         self.search_box = QLineEdit()
#         self.search_box.setPlaceholderText("Search by SSID...")
#         self.search_box.textChanged.connect(self.filter_table)
#         self.search_box.setStyleSheet("padding: 5px; font-size: 12px;")

#         button_group = QGroupBox("Controls")
#         button_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
#         self.start_button = create_button("Start", self.start_scan, "Start scanning for saved Wi-Fi passwords")
#         self.stop_button = create_button("Stop", self.stop_scan, "Stop auto-refresh")
#         self.stop_button.setEnabled(False)
#         self.resume_button = create_button("Resume", self.resume_scan, "Resume scanning")
#         self.resume_button.setEnabled(False)
#         self.reset_button = create_button("Reset", self.reset_table, "Reset to default state")
#         self.save_button = create_button("Save", self.save_results, "Save results to file")

#         button_layout = create_layout([self.start_button, self.stop_button, self.resume_button, self.reset_button, self.save_button], "horizontal")
#         button_group.setLayout(button_layout.layout())

#         self.table = create_table(["Device Name (SSID)", "Password", "Encryption", "Authentication", "Status"], equal_spacing=True)
#         self.table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")  # No font change

#         main_layout = create_layout([self.desc_label, self.status_label, self.search_box, button_group, self.table], stretch_last=True)
#         self.setLayout(main_layout.layout())

#     def start_scan(self):
#         self.start_button.setEnabled(False)
#         self.stop_button.setEnabled(True)
#         self.resume_button.setEnabled(False)
#         self.reset_button.setEnabled(True)
#         self.save_button.setEnabled(True)
#         self.refresh_table()
#         self.timer.start(3000)
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Started successfully")

#     def stop_scan(self):
#         self.timer.stop()
#         self.start_button.setEnabled(True)
#         self.stop_button.setEnabled(False)
#         self.resume_button.setEnabled(True)
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Stopped successfully")

#     def resume_scan(self):
#         self.start_button.setEnabled(False)
#         self.stop_button.setEnabled(True)
#         self.resume_button.setEnabled(False)
#         self.timer.start(3000)
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Resumed successfully")

#     def reset_table(self):
#         self.timer.stop()
#         self.table.setRowCount(0)
#         self.networks.clear()
#         self.total_networks = 0
#         self.start_button.setEnabled(True)
#         self.stop_button.setEnabled(False)
#         self.resume_button.setEnabled(False)
#         self.reset_button.setEnabled(True)
#         self.save_button.setEnabled(False)
#         self.search_box.clear()
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Reset successfully")

#     def save_results(self):
#         text = self.get_results_text()
#         save_to_file(self, lambda fp: save_to_txt(fp, text), "wifi_passwords.txt", "Text Files (*.txt)")
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Saved successfully")

#     def refresh_table(self):
#         self.table.setRowCount(0)
#         self.networks = self.get_saved_networks()
#         self.total_networks = len(self.networks)
#         active_ssid = self.get_active_ssid()
#         for ssid, pwd, enc, auth in self.networks:
#             row = self.table.rowCount()
#             self.table.insertRow(row)
#             self.table.setItem(row, 0, QTableWidgetItem(ssid))
#             self.table.setItem(row, 1, QTableWidgetItem(pwd))
#             self.table.setItem(row, 2, QTableWidgetItem(enc))
#             self.table.setItem(row, 3, QTableWidgetItem(auth))
#             status = "Active" if ssid == active_ssid else "Inactive"
#             self.table.setItem(row, 4, QTableWidgetItem(status))
#         self.status_label.setText(f"Total Networks Found: {self.total_networks} - Refreshed successfully")
#         self.filter_table()

#     def filter_table(self):
#         search_text = self.search_box.text().lower()
#         for row in range(self.table.rowCount()):
#             ssid = self.table.item(row, 0).text().lower()
#             self.table.setRowHidden(row, search_text not in ssid)

#     def get_saved_networks(self):
#         """Retrieve saved Wi-Fi networks with enhanced parsing."""
#         try:
#             files = subprocess.run(["sudo", "ls", "/etc/NetworkManager/system-connections/"], 
#                                    capture_output=True, text=True).stdout.splitlines()
#             networks = {}
#             for file in files:
#                 ssid = file.replace(".nmconnection", "")
#                 result = subprocess.run(["sudo", "cat", f"/etc/NetworkManager/system-connections/{file}"],
#                                        capture_output=True, text=True)
#                 content = result.stdout
#                 networks[ssid] = {"password": "Unknown", "encryption": "Unknown", "auth": "Unknown"}

#                 psk_match = re.search(r"psk=([^\n]+)", content)
#                 psk_flags_match = re.search(r"psk-flags=(\d+)", content)
#                 key_mgmt_match = re.search(r"key-mgmt=([^\n]+)", content)
#                 security_match = re.search(r"802-11-wireless-security\]((?:.*?\n)+?)(?:\n\[|$)", content)

#                 if psk_match and (not psk_flags_match or psk_flags_match.group(1) == "0"):
#                     networks[ssid]["password"] = psk_match.group(1)
#                 elif psk_flags_match and psk_flags_match.group(1) == "1":
#                     networks[ssid]["password"] = "Encrypted (Key not stored)"
#                 elif not security_match and not key_mgmt_match:
#                     networks[ssid]["password"] = "No Password"

#                 if key_mgmt_match:
#                     auth = key_mgmt_match.group(1)
#                     networks[ssid]["auth"] = auth
#                     if "wpa-psk" in auth:
#                         networks[ssid]["encryption"] = "WPA/WPA2 PSK"
#                     elif "wpa-eap" in auth:
#                         networks[ssid]["encryption"] = "WPA/WPA2 EAP"
#                     elif "wep" in auth:
#                         networks[ssid]["encryption"] = "WEP"
#                     elif "none" in auth:
#                         networks[ssid]["encryption"] = "None"
#                         networks[ssid]["password"] = "No Password"
#                 elif not security_match:
#                     networks[ssid]["encryption"] = "Open"
#                     networks[ssid]["auth"] = "None"
#                     networks[ssid]["password"] = "No Password"

#                 if security_match:
#                     security_content = security_match.group(1)
#                     if "wpa-psk" in security_content:
#                         networks[ssid]["encryption"] = "WPA/WPA2 PSK"
#                     elif "wpa-eap" in security_content:
#                         networks[ssid]["encryption"] = "WPA/WPA2 EAP"
#                     elif "wep" in security_content:
#                         networks[ssid]["encryption"] = "WEP"

#             return [(ssid, info["password"], info["encryption"], info["auth"]) for ssid, info in networks.items()]
#         except Exception:
#             return [("Error", "Could not retrieve passwords", "N/A", "N/A")]

#     def get_active_ssid(self):
#         """Get the currently connected SSID."""
#         try:
#             result = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
#             return result.stdout.strip() if result.stdout else None
#         except Exception:
#             return None

#     def get_results_text(self):
#         """Format results as text for saving."""
#         lines = ["Wi-Fi Passwords Report"]
#         for row in range(self.table.rowCount()):
#             if not self.table.isRowHidden(row):
#                 ssid = self.table.item(row, 0).text()
#                 pwd = self.table.item(row, 1).text()
#                 enc = self.table.item(row, 2).text()
#                 auth = self.table.item(row, 3).text()
#                 status = self.table.item(row, 4).text()
#                 lines.append(f"SSID: {ssid}, Password: {pwd}, Encryption: {enc}, Authentication: {auth}, Status: {status}")
#         return "\n".join(lines)




from PyQt6.QtWidgets import QWidget, QTableWidgetItem, QGroupBox, QLabel, QLineEdit
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont
from gui import create_layout, create_button, create_table, save_to_file, save_to_txt
import subprocess
import re
import os
import locale

# Set locale to ensure UTF-8 support
try:
    locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
except locale.Error:
    try:
        locale.setlocale(locale.LC_ALL, "")
    except locale.Error:
        pass
os.environ["LC_ALL"] = "en_US.UTF-8"
os.environ["LANG"] = "en_US.UTF-8"

class WirelessPasswordTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.total_networks = 0
        self.networks = []
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_table)

    def init_ui(self):
        self.desc_label = QLabel("Find the wireless network password of the device which you have previously connected in this device.")
        self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")

        self.status_label = QLabel(f"Total Networks Found: {self.total_networks}")
        self.status_label.setStyleSheet("padding: 5px; font-size: 12px;")

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search by SSID...")
        self.search_box.textChanged.connect(self.filter_table)
        self.search_box.setStyleSheet("padding: 5px; font-size: 12px;")

        button_group = QGroupBox("Controls")
        button_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.start_button = create_button("Start", self.start_scan, "Start scanning for saved Wi-Fi passwords")
        self.stop_button = create_button("Stop", self.stop_scan, "Stop auto-refresh")
        self.stop_button.setEnabled(False)
        self.resume_button = create_button("Resume", self.resume_scan, "Resume scanning")
        self.resume_button.setEnabled(False)
        self.reset_button = create_button("Reset", self.reset_table, "Reset to default state")
        self.save_button = create_button("Save", self.save_results, "Save results to file")

        button_layout = create_layout([self.start_button, self.stop_button, self.resume_button, self.reset_button, self.save_button], "horizontal")
        button_group.setLayout(button_layout.layout())

        self.table = create_table(["Device Name (SSID)", "Password", "Encryption", "Authentication", "Status"], equal_spacing=True)
        self.table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")

        main_layout = create_layout([self.desc_label, self.status_label, self.search_box, button_group, self.table], stretch_last=True)
        self.setLayout(main_layout.layout())

    def start_scan(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.reset_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.refresh_table()
        self.timer.start(3000)
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Started successfully")

    def stop_scan(self):
        self.timer.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Stopped successfully")

    def resume_scan(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.timer.start(3000)
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Resumed successfully")

    def reset_table(self):
        self.timer.stop()
        self.table.setRowCount(0)
        self.networks.clear()
        self.total_networks = 0
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.reset_button.setEnabled(True)
        self.save_button.setEnabled(False)
        self.search_box.clear()
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Reset successfully")

    def save_results(self):
        text = self.get_results_text()
        save_to_file(self, lambda fp: save_to_txt(fp, text), "wifi_passwords.txt", "Text Files (*.txt)")
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Saved successfully")

    def refresh_table(self):
        self.table.setRowCount(0)
        self.networks = self.get_saved_networks()
        self.total_networks = len(self.networks)
        active_ssid = self.get_active_ssid()
        emoji_font = QFont("Noto Color Emoji", 12)  # Font for SSID column only
        default_font = self.table.font()  # Preserve default font for other columns
        for ssid, pwd, enc, auth in self.networks:
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # SSID with emoji support
            ssid_item = QTableWidgetItem(ssid)
            ssid_item.setFont(emoji_font)
            self.table.setItem(row, 0, ssid_item)
            
            # Other columns with default font
            pwd_item = QTableWidgetItem(pwd)
            pwd_item.setFont(default_font)
            self.table.setItem(row, 1, pwd_item)
            
            enc_item = QTableWidgetItem(enc)
            enc_item.setFont(default_font)
            self.table.setItem(row, 2, enc_item)
            
            auth_item = QTableWidgetItem(auth)
            auth_item.setFont(default_font)
            self.table.setItem(row, 3, auth_item)
            
            status_item = QTableWidgetItem("Active" if ssid == active_ssid else "Inactive")
            status_item.setFont(default_font)
            self.table.setItem(row, 4, status_item)
        
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Refreshed successfully")
        self.filter_table()

    def filter_table(self):
        search_text = self.search_box.text().lower()
        for row in range(self.table.rowCount()):
            ssid = self.table.item(row, 0).text().lower()
            self.table.setRowHidden(row, search_text not in ssid)

    def get_saved_networks(self):
        """Retrieve saved Wi-Fi networks with enhanced parsing."""
        try:
            files = subprocess.run(["sudo", "ls", "/etc/NetworkManager/system-connections/"], 
                                   capture_output=True, text=True).stdout.splitlines()
            networks = {}
            for file in files:
                ssid = file.replace(".nmconnection", "")
                result = subprocess.run(["sudo", "cat", f"/etc/NetworkManager/system-connections/{file}"],
                                       capture_output=True, text=True)
                content = result.stdout
                networks[ssid] = {"password": "Unknown", "encryption": "Unknown", "auth": "Unknown"}

                psk_match = re.search(r"psk=([^\n]+)", content)
                psk_flags_match = re.search(r"psk-flags=(\d+)", content)
                key_mgmt_match = re.search(r"key-mgmt=([^\n]+)", content)
                security_match = re.search(r"802-11-wireless-security\]((?:.*?\n)+?)(?:\n\[|$)", content)

                if psk_match and (not psk_flags_match or psk_flags_match.group(1) == "0"):
                    networks[ssid]["password"] = psk_match.group(1)
                elif psk_flags_match and psk_flags_match.group(1) == "1":
                    networks[ssid]["password"] = "Encrypted (Key not stored)"
                elif not security_match and not key_mgmt_match:
                    networks[ssid]["password"] = "No Password"

                if key_mgmt_match:
                    auth = key_mgmt_match.group(1)
                    networks[ssid]["auth"] = auth
                    if "wpa-psk" in auth:
                        networks[ssid]["encryption"] = "WPA/WPA2 PSK"
                    elif "wpa-eap" in auth:
                        networks[ssid]["encryption"] = "WPA/WPA2 EAP"
                    elif "wep" in auth:
                        networks[ssid]["encryption"] = "WEP"
                    elif "none" in auth:
                        networks[ssid]["encryption"] = "None"
                        networks[ssid]["password"] = "No Password"
                elif not security_match:
                    networks[ssid]["encryption"] = "Open"
                    networks[ssid]["auth"] = "None"
                    networks[ssid]["password"] = "No Password"

                if security_match:
                    security_content = security_match.group(1)
                    if "wpa-psk" in security_content:
                        networks[ssid]["encryption"] = "WPA/WPA2 PSK"
                    elif "wpa-eap" in security_content:
                        networks[ssid]["encryption"] = "WPA/WPA2 EAP"
                    elif "wep" in security_content:
                        networks[ssid]["encryption"] = "WEP"

            return [(ssid, info["password"], info["encryption"], info["auth"]) for ssid, info in networks.items()]
        except Exception:
            return [("Error", "Could not retrieve passwords", "N/A", "N/A")]

    def get_active_ssid(self):
        """Get the currently connected SSID."""
        try:
            result = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            return result.stdout.strip() if result.stdout else None
        except Exception:
            return None

    def get_results_text(self):
        """Format results as text for saving."""
        lines = ["Wi-Fi Passwords Report"]
        for row in range(self.table.rowCount()):
            if not self.table.isRowHidden(row):
                ssid = self.table.item(row, 0).text()
                pwd = self.table.item(row, 1).text()
                enc = self.table.item(row, 2).text()
                auth = self.table.item(row, 3).text()
                status = self.table.item(row, 4).text()
                lines.append(f"SSID: {ssid}, Password: {pwd}, Encryption: {enc}, Authentication: {auth}, Status: {status}")
        return "\n".join(lines)