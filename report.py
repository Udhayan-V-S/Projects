from PyQt6.QtWidgets import QWidget, QTextEdit
from gui import create_layout, create_button

class ReportTab(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.init_ui()

    def init_ui(self):
        self.generate_button = create_button("Generate Report", self.generate_report)
        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)

        container = create_layout([self.generate_button, self.report_view])
        self.setLayout(container.layout())

    def generate_report(self):
        # Placeholder: Aggregate data from other tabs later
        report = "wiSpy Report\n\nNetwork: ExampleSSID\nVulnerabilities: WEP Detected"
        self.report_view.setText(report)
        with open("wispy_report.txt", "w") as f:
            f.write(report)