import os
import time
import threading
import sys
import subprocess
import psutil
import requests
from flask import Flask, make_response
from werkzeug.serving import make_server

app = Flask(__name__)
server_thread = None

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

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    print(f"Received request for: {path}")
    redirect_html = """
    <html>
        <head>
            <meta http-equiv="refresh" content="10;url=http://localhost:5000/" />
        </head>
        <body>
            <p>The server is restarting. You will be redirected to the main application in a few moments. If you are not redirected, <a href="http://localhost:5000/">click here</a>.</p>
        </body>
    </html>
    """
    return make_response(redirect_html, 200)

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

def auto_shutdown():
    global server_thread
    if server_thread is not None:
        print("Auto shutdown initiated.")
        server_thread.shutdown()
        server_thread.join()
        print("Server automatically shut down after timeout.")
        sys.exit("Server automatically exited after timeout.")

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

def restart_main_server():
    print("Restarting 'app.py'.")
    app_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'app.py'))
    subprocess.Popen(["python", app_file_path], shell=True)

def wait_for_main_server_to_start(timeout=60):
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_main_server_online("http://localhost:5001"):
            print("Main server is now online.")
            return True
        else:
            print("Waiting for the main server to become online...")
            time.sleep(2)
    return False

if __name__ == '__main__':
    print("Waiting for 1 second before starting.")
    time.sleep(1) 

    restart_main_server()
    if wait_for_main_server_to_start():
        server_thread = ServerThread(app)
        server_thread.start()
#        print("Fallback server running. Will shut down in 20 seconds.")
#        threading.Timer(20, auto_shutdown).start()
    else:
        print("Failed to start the main server within the expected time. Exiting fallback server.")
        sys.exit("Exiting due to main server start failure.")