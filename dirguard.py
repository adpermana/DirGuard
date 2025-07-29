# =====================================================================================
# Directory Guard, real-time directory monitoring and VirusTotal threat detection
# Version: 1.0
# Date   : 2025-07-29
#             .___                                                 
# _____     __| _/_____   ___________  _____ _____    ____ _____   
# \__  \   / __ |\____ \_/ __ \_  __ \/     \\__  \  /    \\__  \  
#  / __ \_/ /_/ ||  |_> >  ___/|  | \/  Y Y  \/ __ \|   |  \/ __ \_
# (____  /\____ ||   __/ \___  >__|  |__|_|  (____  /___|  (____  /
#      \/      \/|__|        \/            \/     \/     \/     \/ 
#
# https://github.com/adpermana/DirGuard
# =====================================================================================

import os
import time
import hashlib
import requests
import shutil
import stat
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# Konfigurasi
VT_API_KEY          = "xxxx"                            # API Key VirusTotal
TELEGRAM_TOKEN      = "xxx:xxxxxxxxxxx"                 # Kode Token Telegram
TELEGRAM_CHAT_ID    = "xxxxx"                           # Kode Chat_ID Telegram
WATCH_DIR           = "/path/directory"                 # sesuaikan dengan Folder yang akan dilakukan monitoring
QUARANTINE_DIR      = "/path/others-dir/quarantine"     # sesuaikan dengan Folder karantina yang menyimpan file terindikasi malicious
ALLOWED_EXTENSIONS  = ['.sh', '.py', '.elf', '.php']    # Ekstensi yang dicek virustotal
MALICIOUS_THRESHOLD = 5                                 # Threshold untuk karantina
SLEEP_INTERVAL      = 15                                # Jeda tunggu setelah upload (detik)

# API Endpoint
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{}"
HEADERS = {"x-apikey": VT_API_KEY}

# Setup awal karantina
def init_quarantine_folder():
    if not os.path.exists(QUARANTINE_DIR):
        os.makedirs(QUARANTINE_DIR, mode=0o700)
    else:
        os.chmod(QUARANTINE_DIR, 0o700)

# Filter ekstensi
def is_allowed_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    return ext in ALLOWED_EXTENSIONS

# SHA256 hash
def get_sha256(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

# Cek file di VT
def vt_lookup(sha256):
    try:
        url = VT_LOOKUP_URL.format(sha256)
        res = requests.get(url, headers=HEADERS)
        if res.status_code == 200:
            data = res.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        elif res.status_code == 404:
            return "Not Found"
        else:
            return "Error ({})".format(res.status_code)
    except Exception as e:
        return "Error: {}".format(e)

# Upload ke VT
def vt_upload(filepath):
    try:
        if os.path.getsize(filepath) > 32 * 1024 * 1024:
            return "File too large (>32MB)"
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            res = requests.post(VT_UPLOAD_URL, headers=HEADERS, files=files)
            if res.status_code == 200:
                return "Uploaded"
            elif res.status_code == 429:
                return "Rate Limited"
            else:
                return "Upload Error ({})".format(res.status_code)
    except Exception as e:
        return "Upload Error: {}".format(e)

# Karantina file
def quarantine_file(filepath):
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
            os.chmod(QUARANTINE_DIR, 0o700)

        filename = os.path.basename(filepath)
        quarantine_path = os.path.join(QUARANTINE_DIR, filename)

        shutil.move(filepath, quarantine_path)
        return quarantine_path
    except Exception as e:
        return "Karantina gagal: {}".format(e)

# Telegram
def send_telegram_message(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_message = "[{}] {}".format(timestamp, msg)

    url = "https://api.telegram.org/bot{}/sendMessage".format(TELEGRAM_TOKEN)
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": full_message,
        "parse_mode": "HTML"
    }
    try:
        requests.post(url, data=data)
    except Exception as e:
        print("Telegram Error:", e)

# Cek file + kirim hasil
def scan_and_alert(filepath, event_type="Detected"):
    sha256 = get_sha256(filepath)
    if not sha256:
        return

    result = vt_lookup(sha256)
    if result == "Not Found":
        upload_result = vt_upload(filepath)
        if upload_result == "Uploaded":
            time.sleep(SLEEP_INTERVAL)
            result = vt_lookup(sha256)
        else:
            result = upload_result

    if isinstance(result, dict):
        malicious = result.get("malicious", 0)
        total = sum(result.values())
        msg = "<b>{}</b>\n<code>{}</code>\n VirusTotal: {}/{}".format(event_type, filepath, malicious, total)

        if malicious >= MALICIOUS_THRESHOLD:
            quarantine_path = quarantine_file(filepath)
            msg += "\n <b>File quarantined!</b>\n <code>{}</code>".format(quarantine_path)
    else:
        msg = " <b>{}</b>\n<code>{}</code>\n  {}".format(event_type, filepath, result)

    send_telegram_message(msg)

# Event handler
class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and os.path.isfile(event.src_path):
            if is_allowed_file(event.src_path):
                scan_and_alert(event.src_path, "File Added")
            else:
                msg = " <b>File Added (skipped VT)</b>\n<code>{}</code>".format(event.src_path)
                send_telegram_message(msg)

    def on_modified(self, event):
        if not event.is_directory and os.path.isfile(event.src_path):
            if is_allowed_file(event.src_path):
                scan_and_alert(event.src_path, "File Modified")
            else:
                msg = " <b>File Modified (skipped VT)</b>\n<code>{}</code>".format(event.src_path)
                send_telegram_message(msg)

    def on_deleted(self, event):
        if not event.is_directory:
            msg = " <b>File Deleted</b>\n<code>{}</code>".format(event.src_path)
            send_telegram_message(msg)

# Main
def main():
    init_quarantine_folder()
    print(" Monitoring folder: {}\n".format(WATCH_DIR))

    handler = FileEventHandler()
    observer = Observer()
    observer.schedule(handler, WATCH_DIR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
