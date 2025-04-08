from PyQt6.QtWidgets import QWidget, QTableWidgetItem, QGroupBox, QLabel
from PyQt6.QtCore import QTimer
from gui import create_layout, create_button, create_table, get_interfaces
import subprocess

class ModeCheckerTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.total_interfaces = 0
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_table)

    def init_ui(self):
        # Description label
        self.desc_label = QLabel("This feature helps you find the interfaces and their mode, which is Monitor or Managed.")
        self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")

        # Status label (will now show action messages)
        self.status_label = QLabel(f"Total Interfaces: {self.total_interfaces}")
        self.status_label.setStyleSheet("padding: 5px; font-size: 12px;")

        # Button group
        button_group = QGroupBox("Controls")
        button_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.start_button = create_button("Start", self.start_check, "Start scanning interface modes")
        self.stop_button = create_button("Stop", self.stop_check, "Stop auto-refresh")
        self.stop_button.setEnabled(False)
        self.refresh_button = create_button("Refresh", self.refresh_table, "Manually refresh table")
        self.reset_button = create_button("Reset", self.reset_table, "Reset to default state")

        button_layout = create_layout([self.start_button, self.stop_button, self.refresh_button, self.reset_button], "horizontal")
        button_group.setLayout(button_layout.layout())

        # Table
        self.table = create_table(["Interface", "Mode"], equal_spacing=True)
        self.table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")

        # Main layout
        main_layout = create_layout([self.desc_label, self.status_label, button_group, self.table], stretch_last=True)
        self.setLayout(main_layout.layout())

    def start_check(self):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.refresh_table()
        self.timer.start(3000)  # Auto-refresh every 3 seconds
        self.status_label.setText(f"Total Interfaces: {self.total_interfaces} - Started successfully")

    def stop_check(self):
        self.timer.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText(f"Total Interfaces: {self.total_interfaces} - Stopped successfully")

    def refresh_table(self):
        self.table.setRowCount(0)
        interfaces = get_interfaces()
        self.total_interfaces = len(interfaces)
        for iface in interfaces:
            mode = self.get_interface_mode(iface)
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(iface))
            self.table.setItem(row, 1, QTableWidgetItem(mode))
        self.status_label.setText(f"Total Interfaces: {self.total_interfaces} - Refreshed successfully")

    def reset_table(self):
        self.timer.stop()
        self.table.setRowCount(0)
        self.total_interfaces = 0
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText(f"Total Interfaces: {self.total_interfaces} - Reset successfully")

    def get_interface_mode(self, iface):
        result = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            return "Monitor"
        elif "Mode:Managed" in result.stdout:
            return "Managed"
        return "Unknown"