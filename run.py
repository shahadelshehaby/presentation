"""Start CodeGuard and open it in the browser.  Double-click run.bat on Windows."""
import os
import sys
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import flask  # noqa: F401
except ImportError:
    print("Flask is not installed for this Python (%s)." % sys.executable)
    print("Install it offline from the USB bundle:  tools\\install_from_usb.bat")
    input("Press Enter to close.")
    sys.exit(1)

import db  # noqa: E402

db.init_db()
s = db.load_settings()
HOST = s.get("host", "127.0.0.1")        # 127.0.0.1 = only this PC can open it (recommended)
PORT = int(s.get("port", 5200))
BROWSER = "http://127.0.0.1:%d" % PORT

from app import app  # noqa: E402

print("CodeGuard - Code Security Scanner")
print("  open:            %s" % BROWSER)
print("  city status:     %s/building/status" % BROWSER)
print("  listening on:    %s:%d   (change 'host' in Settings to share on the network)" % (HOST, PORT))
print("Close this window to stop CodeGuard.")
if "--no-browser" not in sys.argv:
    threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(BROWSER)), daemon=True).start()
app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
