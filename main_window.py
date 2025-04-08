from PyQt6.QtWidgets import QMainWindow, QTabWidget, QMenuBar, QMessageBox, QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt6.QtGui import QAction, QFont
from PyQt6.QtCore import Qt
from network_discovery import NetworkDiscoveryTab
from packet_sniffing import PacketSniffingTab
from report import ReportTab
from mode_checker import ModeCheckerTab
from setting import SettingsTab
from wireless_passwd import WirelessPasswordTab
from gui import create_toolbar, save_to_file, save_to_csv, save_to_txt, save_to_pdf, save_to_pcap

class WiSpyMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("wiSpy - Wireless Eavesdropping Tool")
        self.setGeometry(100, 100, 1000, 700)


        # Menu bar
        self.setup_menu()

        # Toolbar
        self.toolbar = create_toolbar(self)
        self.addToolBar(self.toolbar)

        # Tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Add tabs with reordered sequence
        self.network_tab = NetworkDiscoveryTab(self)
        self.sniffing_tab = PacketSniffingTab(self)
        self.mode_checker_tab = ModeCheckerTab(self)
        self.wireless_passwd_tab = WirelessPasswordTab(self)
        self.report_tab = ReportTab(self)  # Moved to near end
        self.settings_tab = SettingsTab(self)  # Moved to last

        self.tabs.addTab(self.network_tab, "Network Discovery")
        self.tabs.addTab(self.sniffing_tab, "Packet Sniffing")
        self.tabs.addTab(self.mode_checker_tab, "Mode Checker")
        self.tabs.addTab(self.wireless_passwd_tab, "Password Finder")
        self.tabs.addTab(self.report_tab, "Reports & Export")
        self.tabs.addTab(self.settings_tab, "Settings")

        self.monitor_mode = False

    def setup_menu(self):
        menu_bar = QMenuBar(self)
        self.setMenuBar(menu_bar)

        file_menu = menu_bar.addMenu("File")
        new_window_action = QAction("New Window", self)
        new_window_action.triggered.connect(self.open_new_window)
        file_menu.addAction(new_window_action)

        save_menu = file_menu.addMenu("Save")
        save_csv_action = QAction("Save as CSV", self)
        save_csv_action.triggered.connect(self.save_as_csv)
        save_menu.addAction(save_csv_action)
        save_txt_action = QAction("Save as TXT", self)
        save_txt_action.triggered.connect(self.save_as_txt)
        save_menu.addAction(save_txt_action)
        save_pdf_action = QAction("Save as PDF", self)
        save_pdf_action.triggered.connect(self.save_as_pdf)
        save_menu.addAction(save_pdf_action)
        save_pcap_action = QAction("Save as PCAP", self)
        save_pcap_action.triggered.connect(self.save_as_pcap)
        save_menu.addAction(save_pcap_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.confirm_exit)
        file_menu.addAction(exit_action)

        help_menu = menu_bar.addMenu("Help")
        requirements_action = QAction("Requirements", self)
        requirements_action.triggered.connect(self.show_requirements)
        help_menu.addAction(requirements_action)
        docs_action = QAction("Documentation", self)
        docs_action.triggered.connect(self.show_documentation)
        help_menu.addAction(docs_action)
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def open_new_window(self):
        new_window = WiSpyMainWindow()
        new_window.show()

    def save_as_csv(self):
        data = self.get_all_data()
        save_to_file(self, lambda fp: save_to_csv(fp, data), "wispy_data.csv", "CSV Files (*.csv)")

    def save_as_txt(self):
        text = self.get_all_data_text()
        save_to_file(self, lambda fp: save_to_txt(fp, text), "wispy_report.txt", "Text Files (*.txt)")

    def save_as_pdf(self):
        text = self.get_all_data_text()
        save_to_file(self, lambda fp: save_to_pdf(fp, text), "wispy_report.pdf", "PDF Files (*.pdf)")

    def save_as_pcap(self):
        packets = self.get_packet_data()
        save_to_file(self, lambda fp: save_to_pcap(fp, packets), "wispy_capture.pcap", "PCAP Files (*.pcap)")

    def confirm_exit(self):
        reply = QMessageBox.question(self, "Exit wiSpy",
                                     "Do you want to save before exiting?",
                                     QMessageBox.StandardButton.Yes | 
                                     QMessageBox.StandardButton.No | 
                                     QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Yes:
            self.save_as_txt()
            self.close()
        elif reply == QMessageBox.StandardButton.No:
            self.close()

    def show_requirements(self):
        """Show requirements in an enhanced table format."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Requirements")
        layout = QVBoxLayout()

        table = QTableWidget(5, 2)
        table.setHorizontalHeaderLabels(["Requirement", "Installation Command"])
        table.horizontalHeader().setStretchLastSection(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-family: Arial; font-size: 12px; }")

        # Populate table
        requirements = [
            ("PyQt6", "pip install PyQt6"),
            ("Scapy", "pip install scapy"),
            ("aircrack-ng", "sudo apt install aircrack-ng"),
            ("reportlab", "pip install reportlab"),
            ("Root Access", "Run with sudo")
        ]
        for row, (req, cmd) in enumerate(requirements):
            table.setItem(row, 0, QTableWidgetItem(req))
            table.setItem(row, 1, QTableWidgetItem(cmd))

        # Enhance layout
        table.setColumnWidth(0, 150)  # Fixed width for "Requirement"
        table.setColumnWidth(1, 250)  # Wider for "Installation Command"
        table.resizeRowsToContents()
        dialog.resize(450, table.sizeHint().height() + 50)  # Adjusted width and dynamic height

        layout.addWidget(table)
        dialog.setLayout(layout)
        dialog.exec()

    def show_documentation(self):
        QMessageBox.information(self, "Documentation",
                                "wiSpy: Wireless Eavesdropping Tool\n"
                                "Tabs: Network Discovery, Packet Sniffing, Vulnerability Analysis, "
                                "Mode Checker, Password Finder, Reports, Settings")

    def show_about(self):
        QMessageBox.information(self, "About wiSpy",
                                "wiSpy - Wireless Eavesdropping Assessment Tool\n"
                                "Version: 0.1\n"
                                "Built with PyQt6 and Scapy\n"
                                "For authorized penetration testing only.")

    def get_all_data(self):
        networks = self.network_tab.networks.items()
        return [["SSID", "BSSID", "Channel", "Signal", "Encryption"]] + [list([k] + list(v)) for k, v in networks]

    def get_all_data_text(self):
        networks = self.network_tab.networks.items()
        return "\n".join([f"{k}: SSID={v[0]}, Channel={v[1]}, Signal={v[2]}, Encryption={v[3]}" for k, v in networks])

    def get_packet_data(self):
        return []

    def update_mode_status(self):
        pass