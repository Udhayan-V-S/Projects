from PyQt6.QtWidgets import QWidget, QTableWidgetItem, QGroupBox, QLabel, QLineEdit, QMessageBox, QSizePolicy, QInputDialog, QDialog, QVBoxLayout, QTableWidget
from PyQt6.QtCore import QTimer, pyqtSignal, QObject
from gui import create_layout, create_button, create_table, save_to_file, save_to_csv, save_to_txt, save_to_pdf, get_interfaces
import threading
import subprocess
import logging
from scapy.all import sniff, Dot11Beacon, Dot11, Dot11ProbeReq, Dot11ProbeResp, Dot11Deauth, Dot11Auth
from datetime import datetime
import requests
import os
import json
import hashlib
from collections import defaultdict, deque

logging.basicConfig(level=logging.DEBUG, filename="wispy.log", filemode="a", format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

HISTORY_FILE = "ap_history.json"
MAC_API_URL = "https://api.macaddress.io/v1"
MAC_API_KEY = "at_R5VWQqlJ7xPEsm0HE5SzBACnYiQOn"

class ScanSignals(QObject):
    stop_scan = pyqtSignal()
    network_down = pyqtSignal(str)
    error = pyqtSignal(str)

class NetworkDiscoveryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.networks = {}  # {bssid: (ssid, channel, signal, encryption, connected_count, notes, ap_vendor, last_beacon_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes)}
        self.connected_devices = {}  # {bssid: {mac: vendor}}
        self.beacon_times = {}  # {bssid: [timestamps]}
        self.deauth_counts = {}  # {bssid: count}
        self.auth_counts = {}  # {bssid: {success: int, fail: int}}
        self.client_history = {}  # {mac: [(bssid, timestamp)]}
        self.sequence_numbers = {}  # {bssid: [seq_nums]}
        self.probe_requests = {}  # {bssid: {ssid: count}}
        self.packet_rates = {}  # {bssid: deque([rate, timestamp])}
        self.historical_aps = self.load_history()
        self.vendor_cache = {}  # {mac: vendor}
        self.total_networks = 0
        self.interface = "wlan0"  # Default, overridden by SettingsTab
        self.channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        self.current_channel_idx = 0
        self.log_entries = []
        self.scanning = False
        self.scan_thread = None
        self.signals = ScanSignals()
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_table)
        self.signals.stop_scan.connect(self.stop_scan)
        self.signals.network_down.connect(self.handle_network_down)
        self.signals.error.connect(self.handle_error)

    def init_ui(self):
        self.desc_label = QLabel("Enhanced real-time network discovery with vulnerability detection.")
        self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")
        self.status_label = QLabel(f"Total Networks Found: {self.total_networks} | Interface: {self.interface} ({self.get_interface_mode()})")
        self.status_label.setStyleSheet("padding: 5px; font-size: 12px;")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search by SSID, BSSID, or Vendor...")
        self.search_box.textChanged.connect(self.filter_table)
        self.search_box.setStyleSheet("padding: 5px; font-size: 12px;")
        self.search_box.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        button_group = QGroupBox("Controls")
        button_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.start_button = create_button("Start", self.start_scan, "Start scanning")
        self.stop_button = create_button("Stop", self.stop_scan, "Stop scanning")
        self.stop_button.setEnabled(False)
        self.resume_button = create_button("Resume", self.resume_scan, "Resume scanning")
        self.resume_button.setEnabled(False)
        self.reset_button = create_button("Reset", self.reset_table, "Clear table")
        self.save_button = create_button("Save", self.save_results, "Save results")
        self.view_log_button = create_button("View Log", self.view_log, "View logs")
        button_layout = create_layout([self.start_button, self.stop_button, self.resume_button, self.reset_button, self.save_button, self.view_log_button], "horizontal")
        button_group.setLayout(button_layout.layout())
        self.table = create_table(["SSID", "BSSID", "Channel", "Signal (dBm)", "Encryption", "Connected Devices", "Connected MACs", "AP Vendor", "Notes", "Vulnerabilities"], equal_spacing=True)
        self.table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setMinimumHeight(400)
        main_layout = create_layout([self.desc_label, self.status_label, self.search_box, button_group, self.table], stretch_last=True)
        self.setLayout(main_layout.layout())

    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_history(self):
        with open(HISTORY_FILE, 'w') as f:
            json.dump({bssid: {"ssid": ssid, "vendor": ap_vendor, "signal": signal if signal != "?" else -70} for bssid, (ssid, _, signal, _, _, _, ap_vendor, _, _, _, _, _, _, _) in self.networks.items()}, f)

    def get_vendor(self, mac):
        if mac in self.vendor_cache:
            return self.vendor_cache[mac]
        try:
            response = requests.get(f"{MAC_API_URL}?output=json&search={mac}", headers={"X-Authentication-Token": MAC_API_KEY})
            response.raise_for_status()
            vendor = response.json().get("vendorName", "Unknown")
            self.vendor_cache[mac] = vendor
            self.log_debug(f"API lookup: {mac} ---> {vendor}")
            return vendor
        except Exception as e:
            self.log_debug(f"API lookup failed for {mac}: {str(e)}")
            return "Unknown (API Error)"

    def compute_fingerprint(self, packet):
        if packet.haslayer(Dot11Beacon):
            rates = packet.getlayer(Dot11Beacon).network_stats().get('rates', '')
            return hashlib.md5(str(rates).encode()).hexdigest()[:8]
        return "unknown"

    def start_scan(self):
        self.interface = self.parent.settings_tab.iface_combo.currentText()
        monitor_iface = self.get_monitor_interface()
        mode = self.get_interface_mode()
        self.log_debug(f"Starting scan on interface: {self.interface}, mode: {mode}, monitor_iface: {monitor_iface}")
        self.status_label.setText(f"Total Networks Found: {self.total_networks} | Interface: {self.interface} ({mode})")
        
        if not monitor_iface:
            error_msg = f"Interface {self.interface} is not in monitor mode or not found. Enable monitor mode in Settings."
            self.log_debug(error_msg)
            QMessageBox.warning(self, "Monitor Mode Required", error_msg)
            return
        
        try:
            # Test if we can set a channel to ensure permissions
            subprocess.run(["sudo", "iw", "dev", monitor_iface, "set", "channel", "1"], check=True, capture_output=True)
            self.log_debug(f"Successfully tested channel setting on {monitor_iface}")
        except subprocess.CalledProcessError as e:
            error_msg = f"Permission denied or interface issue: {str(e)}. Run with sudo."
            self.log_debug(error_msg)
            QMessageBox.critical(self, "Permission Error", error_msg)
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.reset_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.view_log_button.setEnabled(True)
        self.scanning = True
        self.networks.clear()
        self.connected_devices.clear()
        self.beacon_times.clear()
        self.deauth_counts.clear()
        self.auth_counts.clear()
        self.client_history.clear()
        self.sequence_numbers.clear()
        self.probe_requests.clear()
        self.packet_rates.clear()
        self.log_entries.clear()
        self.table.setRowCount(0)
        self.scan_thread = threading.Thread(target=self.scan_networks, args=(monitor_iface,), daemon=True)
        self.scan_thread.start()
        self.timer.start(1000)
        self.log_debug("Scan thread started and timer activated")

    def stop_scan(self):
        self.scanning = False
        if self.timer.isActive():
            self.timer.stop()
        self.save_history()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Stopped | Interface: {self.interface} ({mode})")
        self.log_debug("Scan stopped")

    def resume_scan(self):
        monitor_iface = self.get_monitor_interface()
        mode = self.get_interface_mode()
        if not monitor_iface:
            error_msg = f"Interface {self.interface} is not in monitor mode or not found. Enable monitor mode in Settings."
            self.log_debug(error_msg)
            QMessageBox.warning(self, "Monitor Mode Required", error_msg)
            return
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.scanning = True
        self.scan_thread = threading.Thread(target=self.scan_networks, args=(monitor_iface,), daemon=True)
        self.scan_thread.start()
        self.timer.start(1000)
        self.log_debug("Scan resumed")

    def reset_table(self):
        self.scanning = False
        if self.timer.isActive():
            self.timer.stop()
        self.networks.clear()
        self.connected_devices.clear()
        self.beacon_times.clear()
        self.deauth_counts.clear()
        self.auth_counts.clear()
        self.client_history.clear()
        self.sequence_numbers.clear()
        self.probe_requests.clear()
        self.packet_rates.clear()
        self.log_entries.clear()
        self.total_networks = 0
        self.table.setRowCount(0)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.search_box.clear()
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Reset | Interface: {self.interface} ({mode})")
        self.log_debug("Table reset")

    def save_results(self):
        mode = self.get_interface_mode()
        formats = ["CSV", "TXT", "PDF"]
        format_choice, ok = QInputDialog.getItem(self, "Save As", "Select format:", formats, 0, False)
        if not ok:
            return
        data = self.get_table_data()
        if format_choice == "CSV":
            save_func = save_to_csv
            default_name = "network_discovery.csv"
            filter_ = "CSV Files (*.csv)"
            formatted_data = [["SSID", "BSSID", "Channel", "Signal (dBm)", "Encryption", "Connected Devices", "Connected MACs", "AP Vendor", "Notes", "Vulnerabilities"]] + data
        elif format_choice == "TXT":
            save_func = save_to_txt
            default_name = "network_discovery.txt"
            filter_ = "Text Files (*.txt)"
            formatted_data = "\n".join([f"SSID: {row[0]}, BSSID: {row[1]}, Channel: {row[2]}, Signal: {row[3]}, Encryption: {row[4]}, Devices: {row[5]}, MACs: {row[6]}, Vendor: {row[7]}, Notes: {row[8]}, Vulnerabilities: {row[9]}" for row in data])
        elif format_choice == "PDF":
            save_func = save_to_pdf
            default_name = "network_discovery.pdf"
            filter_ = "PDF Files (*.pdf)"
            formatted_data = "\n".join([f"SSID: {row[0]}, BSSID: {row[1]}, Channel: {row[2]}, Signal: {row[3]}, Encryption: {row[4]}, Devices: {row[5]}, MACs: {row[6]}, Vendor: {row[7]}, Notes: {row[8]}, Vulnerabilities: {row[9]}" for row in data])
        save_to_file(self, lambda fp: save_func(fp, formatted_data), default_name, filter_)
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Saved as {format_choice} | Interface: {self.interface} ({mode})")
        self.log_debug(f"Results saved as {format_choice}")

    def refresh_table(self):
        self.table.setRowCount(0)
        self.total_networks = len(self.networks)
        channel_counts = {}
        for bssid, (ssid, channel, _, _, _, _, _, _, _, _, _, _, _, _) in self.networks.items():
            if channel != "?":
                channel_counts[channel] = channel_counts.get(channel, 0) + 1
        for bssid, (ssid, channel, signal, encryption, connected_count, notes, ap_vendor, _, _, signal_history, packet_rate, _, snr_history, bssid_changes) in sorted(self.networks.items()):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(ssid))
            self.table.setItem(row, 1, QTableWidgetItem(bssid))
            self.table.setItem(row, 2, QTableWidgetItem(str(channel)))
            self.table.setItem(row, 3, QTableWidgetItem(str(signal)))
            self.table.setItem(row, 4, QTableWidgetItem(encryption))
            self.table.setItem(row, 5, QTableWidgetItem(connected_count))
            macs = "\n".join([f"Device ---> {vendor}" for mac, vendor in sorted(self.connected_devices.get(bssid, {}).items())] or ["None"])
            self.table.setItem(row, 6, QTableWidgetItem(macs))
            self.table.setItem(row, 7, QTableWidgetItem(f"BSSID ---> {ap_vendor}"))

            # Notes
            notes_list = notes.split("; ") if notes else []
            final_notes = "; ".join([n for n in notes_list if n not in ["Safe", "Partially Safe", "Suspicious"]])
            if channel in channel_counts and channel_counts[channel] > 5:
                final_notes = f"{final_notes}; Channel Overlap ({channel_counts[channel]} APs)" if final_notes else f"Channel Overlap ({channel_counts[channel]} APs)"
            if signal_history and max(signal_history) - min(signal_history) > 40:
                final_notes = f"{final_notes}; Signal Instability" if final_notes else "Signal Instability"
            if snr_history and max(snr_history) - min(snr_history) > 20:
                final_notes = f"{final_notes}; SNR Instability" if final_notes else "SNR Instability"
            if bssid_changes > 2:
                final_notes = f"{final_notes}; BSSID Changes ({bssid_changes})" if final_notes else f"BSSID Changes ({bssid_changes})"
            self.table.setItem(row, 8, QTableWidgetItem(final_notes))

            # Vulnerabilities
            vuln_list = []
            if "Open" in encryption:
                vuln_list.append("Open Network")
            if "Duplicate SSID (Suspicious)" in notes_list or "Karma Attack" in notes_list:
                vuln_list.append("Possible Evil Twin")
            if bssid in self.deauth_counts and self.deauth_counts[bssid] > 5:
                vuln_list.append("Deauth Attack")
            if bssid in self.auth_counts and self.auth_counts[bssid]["fail"] > 3:
                fail_rate = self.auth_counts[bssid]["fail"] / (self.auth_counts[bssid]["success"] + self.auth_counts[bssid]["fail"]) if self.auth_counts[bssid]["success"] + self.auth_counts[bssid]["fail"] > 0 else 1
                vuln_list.append(f"Auth Issues ({fail_rate:.0%})")
            if "Suspicious Vendor (ESP32/RPi)" in notes_list:
                vuln_list.append("Suspicious Hardware")
            if packet_rate > 200:
                vuln_list.append("Traffic Burst")
            vuln_str = "; ".join(vuln_list) if vuln_list else "None"
            self.table.setItem(row, 9, QTableWidgetItem(vuln_str))

            self.table.resizeRowToContents(row)
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Refreshed | Interface: {self.interface} ({mode})")
        self.filter_table()

    def filter_table(self):
        search_text = self.search_box.text().lower()
        for row in range(self.table.rowCount()):
            ssid = self.table.item(row, 0).text().lower()
            bssid = self.table.item(row, 1).text().lower()
            ap_vendor = self.table.item(row, 7).text().lower()
            self.table.setRowHidden(row, search_text not in ssid and search_text not in bssid and search_text not in ap_vendor)

    def view_log(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Scan Logs")
        dialog.resize(600, 400)
        layout = QVBoxLayout()
        log_search_box = QLineEdit()
        log_search_box.setPlaceholderText("Search logs...")
        log_search_box.setStyleSheet("padding: 5px; font-size: 12px;")
        log_table = QTableWidget()
        log_table.setColumnCount(2)
        log_table.setHorizontalHeaderLabels(["Timestamp", "Message"])
        log_table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")
        log_table.setRowCount(len(self.log_entries))
        for row, (timestamp, message) in enumerate(self.log_entries):
            log_table.setItem(row, 0, QTableWidgetItem(timestamp))
            log_table.setItem(row, 1, QTableWidgetItem(message))
        log_table.resizeColumnsToContents()
        def filter_log_table():
            search_text = log_search_box.text().lower()
            for row in range(log_table.rowCount()):
                timestamp = log_table.item(row, 0).text().lower()
                message = log_table.item(row, 1).text().lower()
                log_table.setRowHidden(row, search_text not in timestamp and search_text not in message)
        log_search_box.textChanged.connect(filter_log_table)
        layout.addWidget(log_search_box)
        layout.addWidget(log_table)
        dialog.setLayout(layout)
        dialog.exec()

    def log_debug(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_entries.append((timestamp, message))
        logging.debug(message)

    def set_channel(self, iface, channel):
        try:
            subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(channel)], check=True)
            self.log_debug(f"Set channel to {channel} on {iface}")
        except subprocess.CalledProcessError as e:
            self.log_debug(f"Failed to set channel {channel}: {e}")
            raise

    def handle_network_down(self, iface):
        self.scanning = False
        if self.timer.isActive():
            self.timer.stop()
        QMessageBox.warning(self, "Network Error", f"{iface} is no longer in monitor mode. Scan stopped.")
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Stopped (network down) | Interface: {self.interface} ({self.get_interface_mode()})")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        self.log_debug(f"Network down: {iface}")

    def handle_error(self, error_msg):
        self.scanning = False
        if self.timer.isActive():
            self.timer.stop()
        self.status_label.setText(f"Total Networks Found: {self.total_networks} - Error: {error_msg} | Interface: {self.interface} ({self.get_interface_mode()})")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        self.log_debug(f"Error handled: {error_msg}")

    def scan_networks(self, monitor_iface):
        packet_counts = defaultdict(lambda: [0, datetime.now().timestamp()])

        def handle_packet(packet):
            if not self.scanning:
                return
            try:
                self.log_debug(f"Packet captured: {packet.summary()}")
                current_time = datetime.now().timestamp()

                # Packet rate
                bssid = packet[Dot11].addr2.upper() if packet.haslayer(Dot11) and packet.addr2 else None
                if bssid:
                    packet_counts[bssid][0] += 1
                    elapsed = current_time - packet_counts[bssid][1]
                    if elapsed > 1:
                        rate = packet_counts[bssid][0] / elapsed
                        if bssid not in self.packet_rates:
                            self.packet_rates[bssid] = deque(maxlen=10)
                        self.packet_rates[bssid].append((rate, current_time))
                        if bssid in self.networks:
                            self.networks[bssid] = (*self.networks[bssid][:-3], int(rate), *self.networks[bssid][-2:])
                        packet_counts[bssid] = [0, current_time]

                # Beacon handling
                if packet.haslayer(Dot11Beacon):
                    bssid = packet[Dot11].addr2.upper()
                    ssid = packet[Dot11Beacon].info.decode('utf-8', errors='replace') if packet[Dot11Beacon].info else "<Hidden>"
                    channel = "?"
                    if hasattr(packet[Dot11Beacon].payload, 'channel'):
                        chan_val = packet[Dot11Beacon].payload.channel
                        channel = str(chan_val) if isinstance(chan_val, int) else str(ord(chan_val)) if chan_val else "?"
                    signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "?"
                    snr = packet.SNR if hasattr(packet, 'SNR') else "?"
                    encryption = "Open" if not packet[Dot11Beacon].cap.privacy else "WPA/WPA2"
                    ap_vendor = self.get_vendor(bssid)
                    fingerprint = self.compute_fingerprint(packet)
                    seq_num = packet[Dot11].SC >> 4 if hasattr(packet[Dot11], 'SC') else None
                    beacon_fields = (packet[Dot11Beacon].cap, packet[Dot11Beacon].timestamp) if packet.haslayer(Dot11Beacon) else (None, None)

                    # Beacon rate
                    if bssid not in self.beacon_times:
                        self.beacon_times[bssid] = []
                    self.beacon_times[bssid].append(current_time)
                    if len(self.beacon_times[bssid]) > 10:
                        self.beacon_times[bssid].pop(0)
                    beacon_intervals = [self.beacon_times[bssid][i+1] - self.beacon_times[bssid][i] for i in range(len(self.beacon_times[bssid])-1)]
                    avg_interval = sum(beacon_intervals) / len(beacon_intervals) if beacon_intervals else 0.1

                    # Signal and SNR history
                    signal_history = self.networks[bssid][9] if bssid in self.networks else []
                    snr_history = self.networks[bssid][12] if bssid in self.networks else []
                    if signal != "?":
                        signal_history.append(int(signal))
                        if len(signal_history) > 10:
                            signal_history.pop(0)
                    if snr != "?":
                        snr_history.append(int(snr))
                        if len(snr_history) > 10:
                            snr_history.pop(0)

                    # Sequence numbers
                    if seq_num is not None:
                        if bssid not in self.sequence_numbers:
                            self.sequence_numbers[bssid] = []
                        self.sequence_numbers[bssid].append(seq_num)
                        if len(self.sequence_numbers[bssid]) > 20:
                            self.sequence_numbers[bssid].pop(0)

                    # BSSID randomization check
                    bssid_changes = self.networks[bssid][13] if bssid in self.networks else 0
                    if ssid in [v["ssid"] for v in self.historical_aps.values()] and bssid not in self.historical_aps:
                        same_ssid_history = [k for k, v in self.historical_aps.items() if v["ssid"] == ssid]
                        if same_ssid_history:
                            bssid_changes += 1

                    # Detection
                    notes = []
                    suspicion_score = 0

                    if bssid not in self.historical_aps:
                        notes.append("New AP")
                    if bssid in self.historical_aps and signal != "?" and abs(int(signal) - self.historical_aps[bssid]["signal"]) > 30:
                        notes.append("Signal Deviation")
                        suspicion_score += 2

                    if bssid in self.networks:
                        old_channel, old_signal, _, _, _, _, _, _, old_fp, _, _, old_beacon_fields, _, old_bssid_changes = self.networks[bssid]
                        if old_channel != "?" and channel != "?" and old_channel != channel:
                            notes.append("Channel Switch")
                            suspicion_score += 2
                        if old_signal != "?" and signal != "?" and abs(int(old_signal) - int(signal)) > 30:
                            notes.append("Signal Jump")
                            suspicion_score += 2
                        if old_fp != fingerprint:
                            notes.append("Fingerprint Mismatch")
                            suspicion_score += 2
                        if old_beacon_fields[0] != beacon_fields[0] or abs(int(old_beacon_fields[1] or 0) - int(beacon_fields[1] or 0)) > 1000:
                            notes.append("Beacon Inconsistency")
                            suspicion_score += 2

                    # Duplicate SSID
                    same_ssid_aps = [(k, v) for k, v in self.networks.items() if v[0] == ssid and k != bssid]
                    if same_ssid_aps:
                        enterprise_likely = True
                        current_oui = bssid[:8]
                        for other_bssid, (other_ssid, _, _, other_enc, _, _, other_vendor, _, other_fp, _, _, _, _, _) in same_ssid_aps:
                            other_oui = other_bssid[:8]
                            if encryption != other_enc or (current_oui != other_oui and ap_vendor != other_vendor):
                                enterprise_likely = False
                                notes.append("Duplicate SSID (Suspicious)")
                                suspicion_score += 2
                                break
                        if enterprise_likely and len(same_ssid_aps) > 1:
                            notes.append("Enterprise Network")

                    if avg_interval < 0.02 or avg_interval > 1.0:
                        notes.append(f"Unusual Beacon Rate ({avg_interval:.2f}s)")
                        suspicion_score += 1

                    if signal != "?" and int(signal) > -30:
                        notes.append("Strong Signal")
                        suspicion_score += 1

                    if ap_vendor in ["Espressif Inc.", "Raspberry Pi Foundation"]:
                        notes.append("Suspicious Vendor (ESP32/RPi)")
                        suspicion_score += 2
                    elif ap_vendor in ["Android", "Microsoft Corporation", "Apple, Inc."]:
                        notes.append("Possible Hotspot")

                    if bssid in self.sequence_numbers and len(self.sequence_numbers[bssid]) > 10:
                        seq_diffs = [self.sequence_numbers[bssid][i+1] - self.sequence_numbers[bssid][i] for i in range(len(self.sequence_numbers[bssid])-1)]
                        if sum(1 for diff in seq_diffs if diff < 0 or diff > 200) > 3:
                            notes.append("Sequence Anomaly")
                            suspicion_score += 2

                    if bssid in self.packet_rates and len(self.packet_rates[bssid]) > 5:
                        rates = [r[0] for r in self.packet_rates[bssid]]
                        if max(rates) > 2 * sum(rates[:-1]) / (len(rates) - 1):
                            notes.append("Traffic Burst")
                            suspicion_score += 2

                    if "Enterprise Network" in notes and suspicion_score < 3:
                        suspicion_score = 0

                    if suspicion_score >= 3:
                        notes.insert(0, "Suspicious")
                    elif suspicion_score >= 1:
                        notes.insert(0, "Partially Safe")
                    else:
                        notes.insert(0, "Safe")
                    notes_str = "; ".join(notes)

                    if bssid in self.networks:
                        _, old_channel, old_signal, old_enc, old_count, _, old_vendor, _, old_fp, old_signal_history, old_packet_rate, _, old_snr_history, _ = self.networks[bssid]
                        signal = signal if signal != "?" else old_signal
                        encryption = encryption if encryption != "?" else old_enc
                        self.networks[bssid] = (ssid, channel, signal, encryption, old_count, notes_str, ap_vendor, current_time, fingerprint, signal_history, old_packet_rate, beacon_fields, snr_history, bssid_changes)
                    else:
                        self.networks[bssid] = (ssid, channel, signal, encryption, "0", notes_str, ap_vendor, current_time, fingerprint, signal_history, 0, beacon_fields, snr_history, bssid_changes)
                        self.connected_devices[bssid] = {}

                # Probe requests
                if packet.haslayer(Dot11ProbeReq):
                    client = packet[Dot11].addr2.upper()
                    req_ssid = packet[Dot11ProbeReq].info.decode('utf-8', errors='replace')
                    for bssid, (ssid, _, _, _, _, _, _, _, _, _, _, _, _, _) in self.networks.items():
                        if ssid == req_ssid:
                            if bssid not in self.probe_requests:
                                self.probe_requests[bssid] = {}
                            self.probe_requests[bssid][req_ssid] = self.probe_requests[bssid].get(req_ssid, 0) + 1

                # Kara attack
                if packet.haslayer(Dot11ProbeResp):
                    bssid = packet[Dot11].addr2.upper()
                    resp_ssid = packet[Dot11ProbeResp].info.decode('utf-8', errors='replace')
                    if bssid in self.networks and self.networks[bssid][0] != resp_ssid:
                        ssid, channel, signal, encryption, count, notes, ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes = self.networks[bssid]
                        notes_list = notes.split("; ") if notes else []
                        if "Karma Attack" not in notes_list:
                            notes_list.append("Karma Attack")
                            suspicion_score = sum(2 if n in ["Duplicate SSID (Suspicious)", "Suspicious Vendor (ESP32/RPi)"] else 1 for n in notes_list if n not in ["Safe", "Partially Safe", "Suspicious"]) + 2
                            notes_list[0] = "Suspicious" if suspicion_score >= 3 else "Partially Safe"
                            self.networks[bssid] = (ssid, channel, signal, encryption, count, "; ".join(notes_list), ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes)

                # Deauthentication
                if packet.haslayer(Dot11Deauth):
                    bssid = packet[Dot11].addr2.upper()
                    if bssid:
                        self.deauth_counts[bssid] = self.deauth_counts.get(bssid, 0) + 1
                        self.log_debug(f"Deauth packet from {bssid}")

                # Authentication
                if packet.haslayer(Dot11Auth):
                    bssid = packet[Dot11].addr1.upper()
                    if bssid:
                        if bssid not in self.auth_counts:
                            self.auth_counts[bssid] = {"success": 0, "fail": 0}
                        if packet[Dot11Auth].status == 0:
                            self.auth_counts[bssid]["success"] += 1
                        else:
                            self.auth_counts[bssid]["fail"] += 1
                            self.log_debug(f"Auth failure for {bssid}")

                # Connected devices
                if packet.haslayer(Dot11) and packet.type in [1, 2]:
                    src = packet.addr2.upper() if packet.addr2 else None
                    dst = packet.addr1.upper() if packet.addr1 else None
                    bssid = packet.addr3.upper() if hasattr(packet, 'addr3') and packet.addr3 else None
                    if bssid and bssid in self.networks:
                        if src and src != bssid:
                            if src not in self.connected_devices[bssid]:
                                vendor = self.get_vendor(src)
                                self.connected_devices[bssid][src] = vendor
                                self.log_debug(f"Device {src} ---> {vendor} connected to {bssid}")
                            if src not in self.client_history:
                                self.client_history[src] = []
                            self.client_history[src].append((bssid, current_time))
                            if len(self.client_history[src]) > 5 and len(set([x[0] for x in self.client_history[src][-5:]])) > 3:
                                notes_list = self.networks[bssid][5].split("; ") if self.networks[bssid][5] else []
                                if "Rapid Client Switch" not in notes_list:
                                    notes_list.append("Rapid Client Switch")
                                    suspicion_score = sum(2 if n in ["Duplicate SSID (Suspicious)", "Suspicious Vendor (ESP32/RPi)"] else 1 for n in notes_list if n not in ["Safe", "Partially Safe", "Suspicious"]) + 2
                                    notes_list[0] = "Suspicious" if suspicion_score >= 3 else "Partially Safe"
                                    ssid, channel, signal, encryption, count, _, ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes = self.networks[bssid]
                                    self.networks[bssid] = (ssid, channel, signal, encryption, count, "; ".join(notes_list), ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes)
                        if dst and dst != bssid and dst not in self.connected_devices[bssid]:
                            vendor = self.get_vendor(dst)
                            self.connected_devices[bssid][dst] = vendor
                            self.log_debug(f"Device {dst} ---> {vendor} connected to {bssid}")
                        current_count = str(len(self.connected_devices[bssid]))
                        ssid, channel, signal, encryption, _, notes, ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes = self.networks[bssid]
                        self.networks[bssid] = (ssid, channel, signal, encryption, current_count, notes, ap_vendor, last_time, fingerprint, signal_history, packet_rate, beacon_fields, snr_history, bssid_changes)

            except Exception as e:
                self.log_debug(f"Packet parsing error: {str(e)}")

        try:
            self.log_debug(f"Entering scan loop on {monitor_iface}")
            while self.scanning:
                channel = self.channels[self.current_channel_idx]
                self.set_channel(monitor_iface, channel)
                sniff(iface=monitor_iface, prn=handle_packet, count=500, timeout=5)
                self.current_channel_idx = (self.current_channel_idx + 1) % len(self.channels)
                for bssid, (ssid, _, _, _, _, notes, _, _, _, _, _, _, _, _) in self.networks.items():
                    if bssid in self.probe_requests and ssid in self.probe_requests[bssid] and self.probe_requests[bssid][ssid] > 10:
                        notes_list = notes.split("; ") if notes else []
                        if "Probe Ignore" not in notes_list:
                            notes_list.append("Probe Ignore")
                            suspicion_score = sum(2 if n in ["Duplicate SSID (Suspicious)", "Suspicious Vendor (ESP32/RPi)"] else 1 for n in notes_list if n not in ["Safe", "Partially Safe", "Suspicious"]) + 1
                            notes_list[0] = "Suspicious" if suspicion_score >= 3 else "Partially Safe"
                            self.networks[bssid] = (ssid, *self.networks[bssid][1:5], "; ".join(notes_list), *self.networks[bssid][6:])
            self.log_debug("Exited scan loop")
        except OSError as e:
            if "[Errno 100]" in str(e):
                self.signals.network_down.emit(monitor_iface)
            else:
                self.signals.error.emit(str(e))
        except Exception as e:
            self.signals.error.emit(str(e))

    def get_interface_mode(self):
        try:
            result = subprocess.run(["iwconfig", self.interface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                return "Monitor"
            elif "Mode:Managed" in result.stdout:
                return "Managed"
            return "Unknown"
        except Exception as e:
            self.log_debug(f"Error checking interface mode: {str(e)}")
            return "Unknown"

    def get_monitor_interface(self):
        interfaces = get_interfaces()
        for iface in interfaces:
            result = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                return iface
        return None

    def get_table_data(self):
        data = []
        for row in range(self.table.rowCount()):
            if not self.table.isRowHidden(row):
                data.append([self.table.item(row, col).text() for col in range(self.table.columnCount())])
        return data