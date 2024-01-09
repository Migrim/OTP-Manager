import os
import time
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
print(f"Current directory: {current_dir}")

batch_file_path = os.path.join(current_dir, 'restart_app.bat')
print(f"Path to the batch file: {batch_file_path}")

print("Starting the batch file to restart the server.")
subprocess.Popen(["start", "cmd", "/k", batch_file_path], shell=True)

print("Waiting for 5 seconds before killing the server process.")
time.sleep(5)

print("Killing all Python processes.")
subprocess.run(['taskkill', '/f', '/im', 'python.exe'])

print("Server shutdown initiated. The batch file should restart the server.")
