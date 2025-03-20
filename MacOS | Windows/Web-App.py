from flask import Flask
import webview
import threading
import app

def start_flask():
    app.app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()

    webview.create_window('OTP-Manager', 'http://127.0.0.1:5000', width=1000, height=800, resizable=True)
    webview.start(gui='qt')