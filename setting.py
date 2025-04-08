from PyQt6.QtWidgets import QWidget, QGroupBox, QLabel, QMessageBox
from PyQt6.QtCore import QTimer
from gui import create_layout, create_button, create_combo_box, get_interfaces
import subprocess

class SettingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.default_iface = "wlan0"
        self.init_ui()
        # Timer for automatic mode detection
        self.mode_timer = QTimer(self)
        self.mode_timer.timeout.connect(self.update_status)
        self.mode_timer.start(2000)  # Check every 2 seconds

    def init_ui(self):
        self.desc_label = QLabel("If we update anything in the settings, it will change in the whole system and tool settings.")
        self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")

        self.refresh_label = QLabel("")
        self.refresh_label.setStyleSheet("padding: 5px; font-size: 12px;")

        iface_group = QGroupBox("Interface Selection")
        iface_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.iface_combo = create_combo_box(get_interfaces(), self.update_status)
        self.refresh_iface_button = create_button("Refresh", self.refresh_interfaces, "Refresh interface list")
        iface_layout = create_layout([self.iface_combo, self.refresh_iface_button], "horizontal")
        iface_group.setLayout(iface_layout.layout())

        mode_group = QGroupBox("Mode Control")
        mode_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.enable_monitor_button = create_button("Enable Monitor Mode", self.enable_monitor, "Set to monitor mode")
        self.disable_monitor_button = create_button("Switch to Managed Mode", self.disable_monitor, "Set to managed mode")
        self.restart_nm_button = create_button("Restart Network Manager", self.restart_network_manager, "Restart network services")
        mode_layout = create_layout([self.enable_monitor_button, self.disable_monitor_button, self.restart_nm_button], "horizontal")
        mode_group.setLayout(mode_layout.layout())

        save_group = QGroupBox("Settings")
        save_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.save_button = create_button("Save", self.save_settings, "Save and apply settings")
        self.reset_button = create_button("Reset", self.reset_settings, "Restore default settings")
        save_layout = create_layout([self.save_button, self.reset_button], "horizontal")
        save_group.setLayout(save_layout.layout())

        main_layout = create_layout([self.desc_label, iface_group, self.refresh_label, mode_group, save_group], stretch_last=True)
        self.setLayout(main_layout.layout())

    def update_status(self):
        iface = self.iface_combo.currentText()
        mode = self.get_interface_mode(iface)
        self.refresh_label.setText(f"Current Mode for {iface}: {'Monitor' if 'Monitor' in mode else 'Managed'}")

    def refresh_interfaces(self):
        current = self.iface_combo.currentText()
        self.iface_combo.clear()
        self.iface_combo.addItems(get_interfaces())
        self.iface_combo.setCurrentText(current if current in get_interfaces() else self.default_iface)
        self.refresh_label.setText("Refreshed successfully")

    def enable_monitor(self):
        iface = self.iface_combo.currentText()
        mode = self.get_interface_mode(iface)
        if "Monitor" in mode:
            QMessageBox.information(self, "Info", f"{iface} is already in monitor mode")
            self.refresh_label.setText(f"Current Mode for {iface}: Monitor")
            return
        try:
            subprocess.run(["sudo", "nmcli", "dev", "set", iface, "managed", "no"])
            subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
            subprocess.run(["sudo", "iw", iface, "set", "type", "monitor"])
            subprocess.run(["sudo", "ip", "link", "set", iface, "up"])
            mode = self.get_interface_mode(iface)
            if "Monitor" in mode:
                QMessageBox.information(self, "Success", f"Monitor mode enabled successfully for {iface}")
                self.refresh_label.setText(f"Monitor mode enabled for {iface}")
            else:
                raise Exception("Failed to set monitor mode")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to enable monitor mode for {iface}: {str(e)}")
            self.refresh_label.setText(f"Error enabling monitor mode for {iface}")

    def disable_monitor(self):
        iface = self.iface_combo.currentText()
        mode = self.get_interface_mode(iface)
        if "Managed" in mode:
            QMessageBox.information(self, "Info", f"{iface} is already in managed mode")
            self.refresh_label.setText(f"Current Mode for {iface}: Managed")
            return
        try:
            subprocess.run(["sudo", "ip", "link", "set", iface, "down"])
            subprocess.run(["sudo", "iw", iface, "set", "type", "managed"])
            subprocess.run(["sudo", "ip", "link", "set", iface, "up"])
            subprocess.run(["sudo", "nmcli", "dev", "set", iface, "managed", "yes"])
            mode = self.get_interface_mode(iface)
            if "Managed" in mode:
                QMessageBox.information(self, "Success", f"Switched to managed mode successfully for {iface}")
                self.refresh_label.setText(f"Managed mode enabled for {iface}")
            else:
                raise Exception("Failed to set managed mode")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to switch to managed mode for {iface}: {str(e)}")
            self.refresh_label.setText(f"Error switching to managed mode for {iface}")

    def restart_network_manager(self):
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"])
        QMessageBox.information(self, "Success", "Network Manager restarted successfully")
        self.refresh_label.setText("Network Manager restarted")

    def save_settings(self):
        iface = self.iface_combo.currentText()
        mode = self.get_interface_mode(iface)
        self.parent.monitor_mode = "Monitor" in mode
        QMessageBox.information(self, "Success", f"Settings saved for {iface}")
        self.refresh_label.setText("Saved successfully")

    def reset_settings(self):
        iface = self.iface_combo.currentText()
        self.iface_combo.setCurrentText(self.default_iface)
        self.disable_monitor()
        self.parent.monitor_mode = False
        QMessageBox.information(self, "Success", f"Settings reset for {iface}")
        self.refresh_label.setText("Settings reset")

    def get_interface_mode(self, iface):
        result = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
        return result.stdout