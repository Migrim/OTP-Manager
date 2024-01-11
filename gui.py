from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel, QHBoxLayout
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPalette, QColor
import sys
import subprocess
import time

class ServerControl(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'OTP Server Control'
        self.server_process = None
        self.server_start_time = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle(self.title)
        self.setStyleSheet("background-color: #2E2E2E; color: #FFFFFF")

        self.setFixedSize(400, 200)

        layout = QVBoxLayout()

        self.status_label = QLabel("Server is stopped.")
        layout.addWidget(self.status_label)

        self.start_button = QPushButton('Start Server')
        self.start_button.setStyleSheet("background-color: #292D26; color: #77713B")
        self.start_button.setMaximumHeight(40) 
        self.start_button.clicked.connect(self.start_server)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Stop Server')
        self.stop_button.setStyleSheet("background-color: #292D26; color: #77713B")
        self.stop_button.setMaximumHeight(40)
        self.stop_button.clicked.connect(self.stop_server)
        layout.addWidget(self.stop_button)

        self.restart_button = QPushButton('Restart Server')
        self.restart_button.setStyleSheet("background-color: #292D26; color: #77713B")
        self.restart_button.setMaximumHeight(40)  
        self.restart_button.clicked.connect(self.restart_server)
        layout.addWidget(self.restart_button)

        self.uptime_label = QLabel("Uptime: N/A")
        layout.addWidget(self.uptime_label)

        self.setLayout(layout)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_uptime)
        self.timer.start(1000)

    def start_server(self):
        self.server_process = subprocess.Popen(['python', 'app.py'])
        self.server_start_time = time.time()
        self.status_label.setText("Server is running.")

    def stop_server(self):
        if self.server_process:
            self.server_process.kill()
            self.server_start_time = None
            self.status_label.setText("Server is stopped.")

    def restart_server(self):
        self.stop_server()
        self.start_server()
        self.status_label.setText("Server is restarted.")

    def update_uptime(self):
        if self.server_start_time:
            uptime_seconds = int(time.time() - self.server_start_time)
            self.uptime_label.setText(f"Uptime: {uptime_seconds} seconds")
        else:
            self.uptime_label.setText("Uptime: N/A")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ServerControl()
    ex.show()
    sys.exit(app.exec_())
 