# JUDOL SCANNER v2.1

## 🛡️ Tentang Project
**JUDOL SCANNER** adalah tool Python untuk membantu tim keamanan web melakukan analisis terhadap situs yang dicurigai mengalami:

- Hidden iframe injection
- Clickjacking
- Redirect berbahaya
- Hidden gambling links
- Obfuscated JavaScript
- Gambling keyword detection
- CMS detection (WordPress, Joomla, Drupal, Laravel)
- Laporan keamanan TXT / JSON
- Pelaporan DMCA / Kominfo

> Tool ini dibuat untuk kebutuhan **web security assessment** dan investigasi keamanan oleh pihak yang berwenang.

---

## ✨ Fitur

- ✅ Deteksi Iframe Injection (visible & hidden)
- ✅ Deteksi Clickjacking (Security Headers)
- ✅ Deteksi Redirect Berbahaya (Meta / JavaScript / Redirect Chain)
- ✅ Deteksi Hidden Gambling Links
- ✅ Deteksi CSS Hidden Content
- ✅ Deteksi Obfuscated JavaScript & Base64
- ✅ Deteksi `<noscript>` & HTML Comment Injection
- ✅ Gambling Keyword Detection (200+ keyword)
- ✅ CMS Detection (WordPress / Joomla / Drupal / Laravel)
- ✅ WordPress Security Check
- ✅ Batch Scan dari file `.txt`
- ✅ Generate laporan TXT & JSON
- ✅ Gmail SMTP Reporting
- ✅ Generate laporan Kominfo
- ✅ Riwayat Scan

---

## 📦 Requirements

- Python 3.8+
- pip
- Internet connection

Dependencies:

```bash
requests
beautifulsoup4
colorama
tldextract
lxml
urllib3
```

---

## ⚙️ Installation

Clone repository:

```bash
git clone https://github.com/DzkyCx/antijudol
cd judol-scanner
```

Buat virtual environment (disarankan):

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install requests beautifulsoup4 colorama tldextract lxml urllib3
```

Atau jalankan script dan biarkan auto-installer menginstal dependency yang dibutuhkan.

---

## 🚀 Menjalankan Tool

Jalankan:

```bash
python3 judol_scanner.py
```

atau:

```bash
chmod +x judol_scanner.py
./judol_scanner.py
```

---

## 📋 Menu

```text
[1] Scan URL Tunggal
[2] Scan Batch (dari file .txt)
[3] Laporan DMCA & Kominfo
[4] Riwayat Scan
[5] Pengaturan Gmail
[6] Tentang & Channel Pelaporan
[0] Keluar
```

---

## 🔎 Scan URL Tunggal

Pilih menu:

```text
1
```

Masukkan URL:

```text
https://example.com
```

Tool akan menampilkan:

- Risk score
- Redirect chain
- Vulnerabilities
- Gambling links
- Security headers
- Hidden elements
- CMS detection

---

## 📂 Batch Scan

Buat file:

`targets.txt`

Isi:

```text
https://site1.com
https://site2.com
https://site3.com
```

Jalankan menu batch scan:

```text
2
```

Masukkan path file:

```text
targets.txt
```

---

## 📄 Output Report

Report otomatis tersimpan pada folder:

```text
reports/
```

Format:

- TXT Report
- JSON Report
- Batch JSON Report
- Kominfo Report

Contoh:

```text
reports/scan_example_com_20260530_123000.txt
reports/scan_example_com_20260530_123000.json
```

---

## 📧 Gmail SMTP Reporting

Tool mendukung pengiriman laporan via Gmail SMTP.

Gunakan **Google App Password**, bukan password biasa.

Pengaturan:

```text
Menu → Pengaturan Gmail
```

---

## 📢 Channel Pelaporan

- Kominfo: https://aduankonten.id
- Google Safe Browsing:
  https://safebrowsing.google.com/safebrowsing/report_badware/
- Google Gambling Report:
  https://reportcontent.google.com/forms/gambling
- BSSN:
  https://www.bssn.go.id/laporkan-insiden/

---

## ⚠️ Disclaimer

Project ini dibuat untuk:

- Security auditing
- Incident response
- Malware / website injection investigation
- Digital forensics & web security research

Penggunaan yang melanggar hukum atau penyalahgunaan menjadi tanggung jawab pengguna.

---

## 👨‍💻 Author

**Dzky / Tim IT Security**

---

## ⭐ Support

Jika project ini bermanfaat:

- Beri ⭐ di GitHub
- Fork & kontribusi
- Laporkan bug / issue
