from PyQt6.QtWidgets import QVBoxLayout, QHBoxLayout, QWidget, QTableWidget, QPushButton, QToolBar, QFileDialog, QComboBox, QHeaderView
from PyQt6.QtCore import Qt, QTimer
import csv
import os
import subprocess

def create_layout(widget_list, layout_type="vertical", stretch_last=False):
    layout = QVBoxLayout() if layout_type == "vertical" else QHBoxLayout()
    for i, widget in enumerate(widget_list):
        layout.addWidget(widget)
        if stretch_last and i == len(widget_list) - 1:
            layout.addStretch(1)
    container = QWidget()
    container.setLayout(layout)
    return container

def create_button(text, callback=None, tooltip=None):
    button = QPushButton(text)
    button.setStyleSheet("QPushButton { padding: 5px; }")
    if callback:
        button.clicked.connect(callback)
    if tooltip:
        button.setToolTip(tooltip)
    return button

def create_table(columns, equal_spacing=True):
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    header = table.horizontalHeader()
    if equal_spacing:
        for i in range(len(columns)):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
    else:
        header.setStretchLastSection(True)
    table.setAlternatingRowColors(True)
    table.setStyleSheet("QTableWidget { border: 1px solid #d3d3d3; }")
    return table

def create_toolbar(parent):
    toolbar = QToolBar("Main Toolbar", parent)
    toolbar.setMovable(False)
    return toolbar

def create_combo_box(items, callback=None):
    combo = QComboBox()
    combo.addItems(items)
    if callback:
        combo.currentTextChanged.connect(callback)
    return combo

def save_to_file(parent, save_func, default_name, file_filter):
    filepath, _ = QFileDialog.getSaveFileName(parent, f"Save as {file_filter.split()[0]}", default_name, file_filter)
    if filepath:
        result = save_func(filepath)
        return filepath if result else None
    return None

def save_to_csv(filepath, data):
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(data)
    return True

def save_to_txt(filepath, text):
    with open(filepath, 'w') as f:
        f.write(text)
    return True

def save_to_pdf(filepath, text):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        c = canvas.Canvas(filepath, pagesize=letter)
        c.drawString(100, 750, text)
        c.save()
        return True
    except ImportError:
        return False

def save_to_pcap(filepath, packets):
    from scapy.all import wrpcap
    wrpcap(filepath, packets)
    return True

def get_interfaces():
    try:
        result = subprocess.run(["iwconfig"], capture_output=True, text=True)
        return [line.split()[0] for line in result.stdout.splitlines() if "IEEE 802.11" in line]
    except Exception:
        return []