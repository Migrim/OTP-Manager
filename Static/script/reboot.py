import os
import time
import subprocess
import psutil
import requests
from flask import Flask
import threading
import sys
from werkzeug.serving import make_server

app = Flask(__name__)

server_thread = None

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print(f"Received request for: {path}")
    return "The server is restarting. Please try again in a few moments."

@app.route('/shutdown', methods=['POST'])
def shutdown():
    global server_thread
    print("Received shutdown request.")
    if server_thread is not None:
        print("Shutting down the server thread.")
        server_thread.shutdown()
        server_thread.join() 
        print("Server thread successfully shut down.")
        return "Server is shutting down...", 200
    else:
        print("No server thread to shut down.")
        return "Server not running.", 404

class ServerThread(threading.Thread):
    def __init__(self, app):
        threading.Thread.__init__(self)
        self.srv = make_server('127.0.0.1', 5000, app)
        self.ctx = app.app_context()
        self.ctx.push()
        print("Server thread initialized.")

    def run(self):
        print("Starting server thread.")
        self.srv.serve_forever()

    def shutdown(self):
        print("Initiating server thread shutdown.")
        self.srv.shutdown()

def is_main_server_online(url):
    print(f"Checking if the main server is online at: {url}")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("Main server is online.")
            return True
        else:
            print(f"Main server offline, status code: {response.status_code}")
    except requests.ConnectionError:
        print("Connection error occurred while checking main server.")
        return False
    return False

def find_process_id_by_name(process_name):
    print(f"Finding process IDs for process name: {process_name}")
    listOfProcessObjects = []
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
            if process_name.lower() in pinfo['name'].lower() and 'app.py' in pinfo['cmdline']:
                listOfProcessObjects.append(pinfo['pid'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    print(f"Found process IDs: {listOfProcessObjects}")
    return listOfProcessObjects

def run_reboot_procedure():
    global server_thread
    print("Starting reboot procedure.")
    server_thread = ServerThread(app)
    server_thread.start()

    print("Sleeping for 2 seconds to allow server thread to start.")
    time.sleep(2)

    print("Attempting to kill 'app.py' processes.")
    app_pids = find_process_id_by_name('python')
    for pid in app_pids:
        print(f"Killing process ID: {pid}")
        os.kill(pid, os.SIGTERM)

    print("Restarting 'app.py'.")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    batch_file_path = os.path.join(current_dir, 'restart_app.bat')
    subprocess.Popen(["start", "cmd", "/k", batch_file_path], shell=True)

    main_server_url = "http://localhost:5001"
    while not is_main_server_online(main_server_url):
        time.sleep(2)

if server_thread is not None:
    server_thread.shutdown()
    server_thread.join()
    
    # Exit the script
    print("Reboot procedure complete. Exiting script.")
    sys.exit()

if __name__ == '__main__':
    run_reboot_procedure()
