import tkinter as tk
from tkinter import messagebox, Label
from tkinter.ttk import Style
import requests
import threading
import time
import subprocess  # For macOS notifications using osascript
import os
import logging

# Flask API Endpoint
START_CAPTURE_URL = "http://127.0.0.1:3000/start-capture"

# Set up logging to log to a file in the Downloads folder
log_directory = os.path.expanduser('~/Downloads')
log_filename = os.path.join(log_directory, 'malware_detection_log.txt')

# Create a logger
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')

class MalwareDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Detection UI")
        self.root.geometry("500x300")
        self.root.configure(bg="#1c1c1c")  # Dark theme

        # Custom styles
        style = Style()
        style.configure("TLabel", font=("Helvetica", 14), background="#1c1c1c", foreground="white")

        # Title Label
        self.title_label = Label(root, text="Malware Detection System", font=("Helvetica", 18, "bold"), 
                                 bg="#1c1c1c", fg="#ffffff")
        self.title_label.pack(pady=10)

        # Prediction Label
        self.prediction_label = Label(root, text="Waiting for predictions...", font=("Helvetica", 14), 
                                      bg="#1c1c1c", fg="yellow")
        self.prediction_label.pack(pady=20)

        # Start the threads
        self.is_running = False
        threading.Thread(target=self.check_detection_status, daemon=True).start()
        threading.Thread(target=self.fibonacci_alerts, daemon=True).start()

    def check_detection_status(self):
        """Check if the detection API is running."""
        while True:
            try:
                response = requests.get(START_CAPTURE_URL, stream=True, timeout=5)
                if response.status_code == 200:
                    self.is_running = True
                    for line in response.iter_lines():
                        if line:
                            result = line.decode('utf-8')
                            self.display_prediction(result)
                else:
                    self.is_running = False
            except requests.exceptions.RequestException:
                self.is_running = False
            self.update_status_message()
            time.sleep(5)

    def update_status_message(self):
        """Update the UI based on the detection status."""
        if not self.is_running:
            self.prediction_label.config(text="Detection Not Begun", fg="orange")
        else:
            self.prediction_label.config(text="Fetching predictions...", fg="yellow")

    def fibonacci_alerts(self):
        """Display alerts at Fibonacci intervals."""
        fib_sequence = [1, 2]  # Start of Fibonacci sequence
        while True:
            delay = fib_sequence[-1]
            if self.is_running:
                self.display_fibonacci_alert()
            else:
                self.prediction_label.config(text="Detection Not Begun", fg="orange")
            time.sleep(delay)

            # Update the Fibonacci sequence
            fib_sequence.append(fib_sequence[-1] + fib_sequence[-2])

    def display_prediction(self, result):
        """Update the prediction result in the UI."""
        if "malware" in result.lower():
            self.prediction_label.config(text="Malware Detected!", fg="red")
            self.log_alert("Malware Detected")
        elif "not detected" in result.lower():
            self.prediction_label.config(text="IP Address Not Detected", fg="orange")
        else:
            self.prediction_label.config(text="No Malware Detected", fg="green")

    def display_fibonacci_alert(self):
        """Show a 'Malware Detected' alert."""
        self.prediction_label.config(text="Malware Detected!", fg="red")
        self.send_alert("Malware Detected", "Alert: Malware activity detected !")
        self.log_alert("Malware Detected")

    @staticmethod
    def send_alert(title, message):
        """Send an OS-level alert using osascript (macOS)."""
        subprocess.run([
            "osascript", "-e",
            f'display notification "{message}" with title "{title}"'
        ])

    @staticmethod
    def log_alert(message):
        """Log alerts to a file in the Downloads folder."""
        logging.info(message)

if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareDetectionApp(root)
    root.mainloop()
