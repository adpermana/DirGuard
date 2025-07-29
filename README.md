
# DirGuard with AI Contribution

**DirGuard** merupakan Script berbasis Python Code yang dirancang untuk:
- 🛡️ Memantau perubahan pada direktori dan file
- 🔍 Mendeteksi adanya file yang baru ditambahkan, dimodifikasi, dan dilakukan penghapusan
- ☁️ Melakukan pemeriksaan reputasi file melalui integrasi dengan VirusTotal
- 📬 Mengirim notifikasi otomatis ke Telegram

---

## 🚀 Fitur Utama

- Deteksi otomatis file yang **baru ditambahkan**, **dimodifikasi**, atau **dihapus**
- Hitung hash SHA256 dan bandingkan reputasinya di VirusTotal
- Upload file ke VirusTotal jika belum ditemukan hash-nya
- Kirim peringatan ke Telegram secara real-time

---

## ⚙️ Instalasi

1. Pastikan Python 3.5+ terpasang
2. Unduh DirGuard

```bash
git clone https://github.com/adpermana/DirGuard.git
cd DirGuard
```

3. Install dependensi:

```bash
pip install requests watchdog
```

4. Konfigurasi variabel berikut di script:

```python
VT_API_KEY          = "xxxx"                            # API Key VirusTotal
TELEGRAM_TOKEN      = "xxx:xxxxxxxxxxx"                 # Kode Token Telegram
TELEGRAM_CHAT_ID    = "xxxxx"                           # Kode Chat_ID Telegram
WATCH_DIR           = "/path/directory"                 # Folder yang dipantau
QUARANTINE_DIR      = "/path/directory/quarantine"      # Folder karantina
ALLOWED_EXTENSIONS  = ['.sh', '.py', '.elf', '.php']    # Ekstensi yang dicek VT
MALICIOUS_THRESHOLD = 5                                 # Threshold untuk karantina
SLEEP_INTERVAL      = 15                                # Jeda tunggu setelah upload (detik)
```

---

## ▶️ RUN

```bash
python3 dirguard.py
```

## ▶️ RUN BACKGROUND
```bash
python3 dirguard.py &
```
---

## 📦 Contoh Notifikasi Telegram

```
[2025-07-29 09:09:05] File Modified /home/admin/FIM/test.php
VirusTotal: 25/78
File quarantined!
/home/admin/EX/test.php
```
---

## 📜 Lisensi

MIT License

---
