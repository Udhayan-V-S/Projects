import sys
import os
from PyQt6.QtWidgets import QApplication, QMessageBox
from main_window import WiSpyMainWindow

def check_dependencies():
    """Check if required tools and libraries are available."""
    try:
        import scapy  # noqa: F401
        import PyQt6  # noqa: F401
    except ImportError as e:
        return False, f"Missing Python library: {e.name}. Install with 'pip install {e.name}'"
    
    if not os.path.exists("/usr/sbin/airmon-ng"):
        return False, "airmon-ng not found. Install with 'sudo apt install aircrack-ng'"
    
    return True, "All dependencies satisfied"

def main():
    app = QApplication(sys.argv)
    
    # Check dependencies
    deps_ok, deps_message = check_dependencies()
    if not deps_ok:
        QMessageBox.critical(None, "Dependency Error", deps_message)
        sys.exit(1)
    
    # Check if running as root (required for monitor mode)
    if os.geteuid() != 0:
        QMessageBox.critical(None, "Permission Error", "wiSpy must be run with sudo for monitor mode functionality.")
        sys.exit(1)
    
    window = WiSpyMainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()