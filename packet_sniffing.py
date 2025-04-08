from PyQt6.QtWidgets import QWidget, QTableWidgetItem, QGroupBox, QLabel, QLineEdit, QMessageBox, QSizePolicy, QInputDialog, QComboBox, QHBoxLayout
from PyQt6.QtCore import QTimer, pyqtSignal, QObject
from gui import create_layout, create_button, create_table, save_to_file, save_to_csv, get_interfaces
import threading
import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, ARP, Ether, IP, IPv6, TCP, UDP, DNS, ICMP, Raw, wrpcap
import logging
from datetime import datetime
import os
import re
from collections import defaultdict
import socket

logging.basicConfig(level=logging.DEBUG, filename="wispy.log", filemode="a", format="%(asctime)s - %(levelname)s - %(message)s")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)

class SniffSignals(QObject):
    stop_sniff = pyqtSignal()
    network_down = pyqtSignal(str)
    error = pyqtSignal(str)

class PacketSniffingTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.interface = "wlan0"
        self.packets = []
        self.sniffing = False
        self.sniff_thread = None
        self.signals = SniffSignals()
        self.captured_raw_packets = []
        self.sniff_mode = "Managed"
        self.target_mac = None
        self.packet_counts = defaultdict(int)
        self.packet_rates = defaultdict(lambda: [0, datetime.now().timestamp()])
        self.domain_cache = {}  # Cache for reverse DNS lookups
        self.init_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_table)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        self.signals.stop_sniff.connect(self.stop_sniff)
        self.signals.network_down.connect(self.handle_network_down)
        self.signals.error.connect(self.handle_error)

    def init_ui(self):
        self.desc_label = QLabel("Advanced packet capture with real-time analysis and periodic updates.")
        self.desc_label.setStyleSheet("padding: 5px; font-weight: bold; font-size: 14px;")

        self.status_label = QLabel(f"Total Packets Captured: {len(self.packets)} | Interface: {self.interface} ({self.get_interface_mode()})")
        self.status_label.setStyleSheet("padding: 5px; font-size: 12px;")

        # Configuration Group
        config_group = QGroupBox("Configuration")
        config_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(get_interfaces() or ["No interfaces found"])
        self.iface_combo.currentTextChanged.connect(self.update_interface)
        self.refresh_iface_button = create_button("Refresh", self.refresh_interfaces, "Refresh interface list")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Managed", "Monitor", "Specific Device"])
        self.mode_combo.setCurrentText("Managed")
        self.mode_combo.currentTextChanged.connect(self.update_mode)
        self.mac_input = QLineEdit()
        self.mac_input.setPlaceholderText("Enter MAC (e.g., AA:BB:CC:DD:EE:FF)")
        self.mac_input.setEnabled(False)
        self.mac_input.textChanged.connect(self.update_target_mac)
        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("Interface:"))
        config_layout.addWidget(self.iface_combo)
        config_layout.addWidget(self.refresh_iface_button)
        config_layout.addWidget(QLabel("Mode:"))
        config_layout.addWidget(self.mode_combo)
        config_layout.addWidget(QLabel("Target MAC:"))
        config_layout.addWidget(self.mac_input)
        config_group.setLayout(config_layout)

        # Filter Group
        filter_group = QGroupBox("Packet Filter")
        filter_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "HTTP/HTTPS", "DNS", "TCP", "UDP", "ARP", "ICMP", "802.11"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by MAC, IP, Port, Domain, URI, Server, Rate...")
        self.search_box.textChanged.connect(self.filter_table)
        self.search_box.setStyleSheet("padding: 5px; font-size: 12px;")
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.search_box)
        filter_group.setLayout(filter_layout)

        # Controls
        button_group = QGroupBox("Controls")
        button_group.setStyleSheet("QGroupBox { font-weight: bold; padding: 10px; }")
        self.start_button = create_button("Start", self.start_sniff, "Start packet capture")
        self.stop_button = create_button("Stop", self.stop_sniff, "Stop packet capture")
        self.stop_button.setEnabled(False)
        self.resume_button = create_button("Resume", self.resume_sniff, "Resume packet capture")
        self.resume_button.setEnabled(False)
        self.reset_button = create_button("Reset", self.reset_table, "Clear table and reset")
        self.save_button = create_button("Save", self.save_results, "Save captured packets")
        self.stats_button = create_button("Stats", self.show_stats, "Show packet statistics")
        self.capture_duration_combo = QComboBox()
        self.capture_duration_combo.addItems(["10s", "30s", "60s", "Manual"])
        self.capture_duration_combo.setCurrentText("Manual")
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.resume_button)
        button_layout.addWidget(self.reset_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.stats_button)
        button_layout.addWidget(QLabel("Duration:"))
        button_layout.addWidget(self.capture_duration_combo)
        button_group.setLayout(button_layout)

        self.table = create_table(
            ["Timestamp", "IP", "MAC", "Port", "Version", "Service", "Domain Name", "Website URI", "Server", "Flags", "Rate (pkt/s)", "Packet Size"],
            equal_spacing=True
        )
        self.table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; font-size: 12px; }")
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.table.setMinimumHeight(400)

        main_layout = create_layout([self.desc_label, self.status_label, config_group, filter_group, button_group, self.table], stretch_last=True)
        self.setLayout(main_layout.layout())

    def refresh_interfaces(self):
        self.iface_combo.clear()
        interfaces = get_interfaces() or ["No interfaces found"]
        self.iface_combo.addItems(interfaces)
        self.interface = self.iface_combo.currentText()
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} | Interface: {self.interface} ({self.get_interface_mode()})")
        self.log_debug("Interfaces refreshed")

    def update_interface(self, iface):
        self.interface = iface
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} | Interface: {self.interface} ({self.get_interface_mode()})")

    def update_mode(self, mode):
        self.sniff_mode = mode
        self.mac_input.setEnabled(mode == "Specific Device")
        if mode != "Specific Device":
            self.target_mac = None
            self.mac_input.clear()
        self.log_debug(f"Mode changed to {mode}")

    def update_target_mac(self, text):
        if self.sniff_mode == "Specific Device":
            mac = text.strip().lower()
            if re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
                self.target_mac = mac
                self.log_debug(f"Target MAC set to {self.target_mac}")
            else:
                self.target_mac = None
                self.log_debug("Invalid MAC address format")

    def start_sniff(self):
        self.interface = self.iface_combo.currentText()
        monitor_iface = self.get_monitor_interface()
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} | Interface: {self.interface} ({mode})")

        if self.sniff_mode in ["Monitor", "Specific Device"] and not monitor_iface:
            QMessageBox.warning(self, "Monitor Mode Required", f"Enable monitor mode for {self.interface} (e.g., 'sudo airmon-ng start {self.interface}').")
            return
        if self.sniff_mode == "Specific Device" and not self.target_mac:
            QMessageBox.warning(self, "MAC Required", "Enter a valid MAC address for Specific Device mode.")
            return

        sniff_iface = monitor_iface if self.sniff_mode in ["Monitor", "Specific Device"] else self.interface
        try:
            subprocess.run(["sudo", "ip", "link", "set", sniff_iface, "up"], check=True, capture_output=True)
            self.log_debug(f"Interface {sniff_iface} is up")
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Permission Error", f"Failed to bring up {sniff_iface}: {str(e)}. Run with sudo.")
            return

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.reset_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.stats_button.setEnabled(True)
        self.sniffing = True
        self.packets.clear()
        self.captured_raw_packets.clear()
        self.packet_counts.clear()
        self.packet_rates.clear()
        self.table.setRowCount(0)
        
        duration = self.capture_duration_combo.currentText()
        timeout = None if duration == "Manual" else int(duration[:-1])
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(sniff_iface, timeout), daemon=True)
        self.sniff_thread.start()
        self.log_debug(f"Packet sniffing started with duration: {duration}")

    def stop_sniff(self):
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Stopped | Interface: {self.interface} ({mode})")
        self.log_debug("Packet sniffing stopped")

    def resume_sniff(self):
        monitor_iface = self.get_monitor_interface()
        mode = self.get_interface_mode()
        if self.sniff_mode in ["Monitor", "Specific Device"] and not monitor_iface:
            QMessageBox.warning(self, "Monitor Mode Required", f"Enable monitor mode for {self.interface}.")
            return
        if self.sniff_mode == "Specific Device" and not self.target_mac:
            QMessageBox.warning(self, "MAC Required", "Enter a valid MAC address for Specific Device mode.")
            return
        sniff_iface = monitor_iface if self.sniff_mode in ["Monitor", "Specific Device"] else self.interface
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.sniffing = True
        duration = self.capture_duration_combo.currentText()
        timeout = None if duration == "Manual" else int(duration[:-1])
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(sniff_iface, timeout), daemon=True)
        self.sniff_thread.start()
        self.log_debug("Packet sniffing resumed")

    def reset_table(self):
        self.sniffing = False
        self.packets.clear()
        self.captured_raw_packets.clear()
        self.packet_counts.clear()
        self.packet_rates.clear()
        self.table.setRowCount(0)
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.search_box.clear()
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Reset | Interface: {self.interface} ({mode})")
        self.log_debug("Table reset")

    def save_results(self):
        mode = self.get_interface_mode()
        formats = ["CSV", "PCAP"]
        format_choice, ok = QInputDialog.getItem(self, "Save As", "Select file format:", formats, 0, False)
        if not ok:
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if format_choice == "CSV":
            data = [[str(p[0]), str(p[1]), str(p[2]), str(p[3]), str(p[4]), str(p[5]), str(p[6]), str(p[7]), str(p[8]), str(p[9]), str(p[10]), str(p[11])] for p in self.packets]
            save_func = save_to_csv
            default_name = f"packet_capture_{timestamp}.csv"
            filter_ = "CSV Files (*.csv)"
            formatted_data = [["Timestamp", "IP", "MAC", "Port", "Version", "Service", "Domain Name", "Website URI", "Server", "Flags", "Rate (pkt/s)", "Packet Size"]] + data
            save_to_file(self, lambda fp: save_func(fp, formatted_data), default_name, filter_)
        elif format_choice == "PCAP":
            if not self.captured_raw_packets:
                QMessageBox.warning(self, "Save Error", "No packets captured to save as PCAP.")
                return
            default_name = f"packet_capture_{timestamp}.pcap"
            filter_ = "PCAP Files (*.pcap)"
            save_to_file(self, lambda fp: wrpcap(fp, self.captured_raw_packets), default_name, filter_)

        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Saved as {format_choice} | Interface: {self.interface} ({mode})")
        self.log_debug(f"Results saved as {format_choice}")

    def auto_save_and_reset(self):
        if len(self.packets) >= 2500:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"packet_capture_{timestamp}.csv"
            data = [[str(p[0]), str(p[1]), str(p[2]), str(p[3]), str(p[4]), str(p[5]), str(p[6]), str(p[7]), str(p[8]), str(p[9]), str(p[10]), str(p[11])] for p in self.packets]
            formatted_data = [["Timestamp", "IP", "MAC", "Port", "Version", "Service", "Domain Name", "Website URI", "Server", "Flags", "Rate (pkt/s)", "Packet Size"]] + data
            save_to_csv(filename, formatted_data)
            self.log_debug(f"Auto-saved {len(self.packets)} packets to {filename}")
            self.packets.clear()
            self.captured_raw_packets.clear()
            self.packet_counts.clear()
            self.packet_rates.clear()
            self.table.setRowCount(0)
            self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Auto-saved and reset | Interface: {self.interface} ({self.get_interface_mode()})")

    def show_stats(self):
        stats = f"Packet Statistics:\nTotal Packets: {len(self.packets)}\n"
        protocols = defaultdict(int)
        total_size = 0
        for _, _, _, _, _, service, _, _, _, _, _, size in self.packets:
            proto = service.split(" ")[0]
            protocols[proto] += 1
            total_size += int(size)
        stats += "Protocol Breakdown:\n" + "\n".join([f"{proto}: {count}" for proto, count in protocols.items()])
        stats += f"\nTotal Data Size: {total_size} bytes"
        if self.sniff_mode == "Specific Device" and self.target_mac:
            stats += f"\nTarget MAC: {self.target_mac}"
        QMessageBox.information(self, "Packet Statistics", stats)
        self.log_debug("Displayed packet statistics")

    def apply_filter(self, filter_type):
        self.filter_table()

    def refresh_table(self):
        self.auto_save_and_reset()
        self.table.setRowCount(0)
        for timestamp, ip, mac, port, version, service, domain, uri, server, flags, rate, size in self.packets:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(timestamp)))
            self.table.setItem(row, 1, QTableWidgetItem(str(ip)))
            self.table.setItem(row, 2, QTableWidgetItem(str(mac)))
            self.table.setItem(row, 3, QTableWidgetItem(str(port)))
            self.table.setItem(row, 4, QTableWidgetItem(str(version)))
            self.table.setItem(row, 5, QTableWidgetItem(str(service)))
            self.table.setItem(row, 6, QTableWidgetItem(str(domain)))
            self.table.setItem(row, 7, QTableWidgetItem(str(uri)))
            self.table.setItem(row, 8, QTableWidgetItem(str(server)))
            self.table.setItem(row, 9, QTableWidgetItem(str(flags)))
            self.table.setItem(row, 10, QTableWidgetItem(str(rate)))
            self.table.setItem(row, 11, QTableWidgetItem(str(size)))
            self.table.resizeRowToContents(row)
        mode = self.get_interface_mode()
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Refreshed | Interface: {self.interface} ({mode})")
        self.filter_table()

    def filter_table(self):
        search_text = self.search_box.text().lower()
        filter_type = self.filter_combo.currentText()
        for row in range(self.table.rowCount()):
            ip = self.table.item(row, 1).text().lower()
            mac = self.table.item(row, 2).text().lower()
            port = self.table.item(row, 3).text().lower()
            version = self.table.item(row, 4).text().lower()
            service = self.table.item(row, 5).text().lower()
            domain = self.table.item(row, 6).text().lower()
            uri = self.table.item(row, 7).text().lower()
            server = self.table.item(row, 8).text().lower()
            flags = self.table.item(row, 9).text().lower()
            rate = self.table.item(row, 10).text().lower()
            size = self.table.item(row, 11).text().lower()

            filter_match = True
            if filter_type != "All":
                if filter_type == "HTTP/HTTPS" and "http" not in service:
                    filter_match = False
                elif filter_type == "DNS" and "dns" not in service:
                    filter_match = False
                elif filter_type == "TCP" and "tcp" not in service:
                    filter_match = False
                elif filter_type == "UDP" and "udp" not in service:
                    filter_match = False
                elif filter_type == "ARP" and "arp" not in service:
                    filter_match = False
                elif filter_type == "ICMP" and "icmp" not in service:
                    filter_match = False
                elif filter_type == "802.11" and not any(x in service for x in ["beacon", "probe"]):
                    filter_match = False

            text_match = (search_text in ip or search_text in mac or search_text in port or search_text in version or 
                          search_text in service or search_text in domain or search_text in uri or search_text in server or 
                          search_text in flags or search_text in rate or search_text in size)

            self.table.setRowHidden(row, not (filter_match and (not search_text or text_match)))

    def handle_network_down(self, iface):
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        QMessageBox.warning(self, "Network Error", f"{iface} is no longer available. Sniffing stopped.")
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Stopped (network down) | Interface: {self.interface} ({self.get_interface_mode()})")

    def handle_error(self, error_msg):
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        self.status_label.setText(f"Total Packets Captured: {len(self.packets)} - Error: {error_msg} | Interface: {self.interface} ({self.get_interface_mode()})")
        self.log_debug(f"Sniffing error: {error_msg}")

    def sniff_packets(self, sniff_iface, timeout=None):
        def handle_packet(packet):
            if not self.sniffing:
                return
            try:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ip = "Unknown"
                mac = "Unknown"
                port = "Unknown"
                version = "Unknown"
                service = "Unknown"
                domain = "Unknown"
                uri = "Unknown"
                server = "Unknown"
                flags = "None"
                rate = 0
                size = len(packet)

                # Packet rate calculation
                current_time = datetime.now().timestamp()
                key = None
                if packet.haslayer(IP):
                    key = packet[IP].src
                elif packet.haslayer(IPv6):
                    key = packet[IPv6].src
                elif packet.haslayer(Dot11):
                    key = packet[Dot11].addr2 if packet[Dot11].addr2 else "Unknown"
                if key:
                    self.packet_rates[key][0] += 1
                    elapsed = current_time - self.packet_rates[key][1]
                    if elapsed > 1:
                        rate = int(self.packet_rates[key][0] / elapsed)
                        self.packet_rates[key] = [0, current_time]

                # Mode-specific filtering
                if self.sniff_mode == "Managed":
                    if not (packet.haslayer(Ether) or packet.haslayer(IP) or packet.haslayer(IPv6) or packet.haslayer(ARP) or 
                            packet.haslayer(TCP) or packet.haslayer(UDP)):
                        return
                elif self.sniff_mode == "Specific Device":
                    if not packet.haslayer(Dot11) or (self.target_mac not in [packet[Dot11].addr1, packet[Dot11].addr2, packet[Dot11].addr3]):
                        return

                # MAC Layer
                if packet.haslayer(Ether):
                    src_mac = packet[Ether].src if packet[Ether].src else "Unknown"
                    dst_mac = packet[Ether].dst if packet[Ether].dst else "Unknown"
                    mac = f"Src: {src_mac}\nDst: {dst_mac}"
                elif packet.haslayer(Dot11):
                    src_mac = packet[Dot11].addr2 if packet[Dot11].addr2 else "Unknown"
                    dst_mac = packet[Dot11].addr1 if packet[Dot11].addr1 else "Unknown"
                    mac = f"Src: {src_mac}\nDst: {dst_mac}"

                # IP Layer with Reverse DNS
                if packet.haslayer(IP):
                    ip = f"Src: {packet[IP].src}\nDst: {packet[IP].dst}"
                    version = "IPv4"
                    flags = f"Flags: {packet[IP].flags}"
                    self.packet_counts[packet[IP].src] += 1
                    server = self.reverse_dns(packet[IP].dst) if packet[IP].dst != "Unknown" else packet[IP].dst
                elif packet.haslayer(IPv6):
                    ip = f"Src: {packet[IPv6].src}\nDst: {packet[IPv6].dst}"
                    version = "IPv6"
                    self.packet_counts[packet[IPv6].src] += 1
                    server = self.reverse_dns(packet[IPv6].dst) if packet[IPv6].dst != "Unknown" else packet[IPv6].dst

                # Transport Layer
                if packet.haslayer(TCP):
                    port = f"Src: {packet[TCP].sport}\nDst: {packet[TCP].dport}"
                    service = "TCP"
                    flags = f"Flags: {packet[TCP].flags}"
                    if rate > 100:
                        service += " (High Rate)"
                elif packet.haslayer(UDP):
                    port = f"Src: {packet[UDP].sport}\nDst: {packet[UDP].dport}"
                    service = "UDP"
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        service = "UDP/DNS"

                # Application Layer - Enhanced Analysis
                if packet.haslayer(TCP) and (packet[TCP].sport in [80, 443] or packet[TCP].dport in [80, 443]):
                    service = "HTTP" if packet[TCP].sport == 80 or packet[TCP].dport == 80 else "HTTPS"
                    raw = packet.getlayer(Raw)
                    if raw:
                        payload = raw.load.decode('utf-8', errors='ignore')
                        if "Host:" in payload:
                            host = payload.split("Host:")[1].split("\n")[0].strip()
                            domain = host
                            server = host
                        if "GET " in payload or "POST " in payload:
                            uri = payload.split(" ")[1] if " " in payload else "Unknown"
                        if uri != "Unknown" and re.search(r"(login|admin|phpmyadmin)", uri, re.IGNORECASE):
                            service += " (Suspicious URI)"
                    elif packet[TCP].dport == 443 and packet.haslayer(IP):
                        domain = self.reverse_dns(packet[IP].dst) if packet[IP].dst not in self.domain_cache else self.domain_cache[packet[IP].dst]
                elif packet.haslayer(DNS):
                    if packet[DNS].qr == 0:  # Query
                        domain = packet[DNS].qname.decode('utf-8', errors='ignore') if packet[DNS].qname else "Unknown"
                        server = packet[IP].dst if packet.haslayer(IP) else "Unknown"
                    else:  # Response
                        domain = packet[DNS].an.rdata if packet[DNS].an else "Unknown"
                        server = packet[IP].src if packet.haslayer(IP) else "Unknown"
                        if packet.haslayer(IP):
                            self.domain_cache[packet[IP].dst] = domain
                    service = "DNS"
                    if self.packet_counts.get(domain, 0) > 50:
                        service += " (DNS Flood?)"
                    self.packet_counts[domain] += 1

                # ARP
                if packet.haslayer(ARP):
                    ip = f"Src: {packet[ARP].psrc}\nDst: {packet[ARP].pdst}"
                    mac = f"Src: {packet[ARP].hwsrc}\nDst: {packet[ARP].hwdst}"
                    service = "ARP"
                    version = "N/A"
                    server = packet[ARP].pdst
                    if self.packet_counts.get(packet[ARP].psrc, 0) > 20:
                        service += " (ARP Flood?)"
                    self.packet_counts[packet[ARP].psrc] += 1

                # ICMP
                if packet.haslayer(ICMP):
                    ip = f"Src: {packet[IP].src}\nDst: {packet[IP].dst}"
                    service = "ICMP"
                    version = "IPv4"
                    server = self.reverse_dns(packet[IP].dst)
                    if self.packet_counts.get(packet[IP].src, 0) > 50:
                        service += " (Ping Flood?)"

                # 802.11-specific
                if self.sniff_mode in ["Monitor", "Specific Device"]:
                    if packet.haslayer(Dot11Beacon):
                        service = "Beacon"
                        domain = packet[Dot11Beacon].info.decode('utf-8', errors='ignore') if packet[Dot11Beacon].info else "<Hidden>"
                        server = "Broadcast"
                        if domain in self.packet_counts and self.packet_counts[domain] > 5:
                            service += " (Duplicate SSID)"
                        self.packet_counts[domain] += 1
                    elif packet.haslayer(Dot11ProbeReq):
                        service = "Probe Request"
                        domain = packet[Dot11ProbeReq].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeReq].info else "Unknown"
                        server = "Unknown"
                    elif packet.haslayer(Dot11ProbeResp):
                        service = "Probe Response"
                        domain = packet[Dot11ProbeResp].info.decode('utf-8', errors='ignore') if packet[Dot11ProbeResp].info else "Unknown"
                        server = packet[Dot11].addr3 if packet[Dot11].addr3 else "Unknown"

                self.packets.append((timestamp, ip, mac, port, version, service, domain, uri, server, flags, rate, size))
                self.captured_raw_packets.append(packet)
                self.log_debug(f"Captured packet: {service} from {ip}, Domain: {domain}, URI: {uri}, Server: {server}, Size: {size}")

            except Exception as e:
                self.log_debug(f"Packet parsing error: {str(e)}")

        try:
            sniff(iface=sniff_iface, prn=handle_packet, store=0, timeout=timeout, stop_filter=lambda p: not self.sniffing)
            self.sniffing = False  # Stop after timeout
            self.stop_sniff()
        except OSError as e:
            if "[Errno 100]" in str(e):
                self.signals.network_down.emit(sniff_iface)
            else:
                self.signals.error.emit(str(e))
        except Exception as e:
            self.signals.error.emit(str(e))

    def reverse_dns(self, ip):
        if ip in self.domain_cache:
            return self.domain_cache[ip]
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.domain_cache[ip] = domain
            return domain
        except (socket.herror, socket.gaierror):
            return ip

    def get_interface_mode(self):
        try:
            result = subprocess.run(["iwconfig", self.interface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                return "Monitor"
            elif "Mode:Managed" in result.stdout:
                return "Managed"
            return "Unknown"
        except Exception:
            return "Unknown"

    def get_monitor_interface(self):
        interfaces = get_interfaces()
        for iface in interfaces:
            result = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
            if "Mode:Monitor" in result.stdout:
                return iface
        return None

    def log_debug(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.debug(f"{timestamp} - {message}")