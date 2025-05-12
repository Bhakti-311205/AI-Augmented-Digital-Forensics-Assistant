# 🧠 AI-Augmented Digital Forensics Assistant

A lightweight, modular, AI-powered tool for digital forensics analysis, combining log anomaly detection, file and image metadata extraction, and malware detection via VirusTotal integration.

---

## ❗ Problem Statement

Traditional digital forensics tools are either overly complex or lack real-time intelligent analysis. Investigators often struggle with:

- Time-consuming manual review of log files
- Missing or altered file metadata
- Identifying malicious files without sandboxing
- Lack of visual insights (e.g., GPS from image EXIF)

This tool solves these issues by combining **AI-based anomaly detection** and **automated metadata extraction** in a beginner-friendly, browser-accessible app.

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| 📁 **File Metadata Analyzer** | Extracts size, timestamps, type, hash (MD5/SHA256), and checks VirusTotal threat score. |
| 📊 **AI Log Anomaly Detection** | Detects unusual behavior in system log files using Isolation Forest. |
| 🖼️ **Image Metadata Viewer** | Extracts EXIF metadata and maps GPS coordinates using Folium. |
| 🛡️ **Malware Detection** | Uses VirusTotal to check if file hash is malicious, suspicious, or clean. |


---

## 🛠️ Setup Instructions

### 🔗 Prerequisites

- Python 3.10+
- Internet connection (for VirusTotal API)
- VirusTotal API key (free at https://www.virustotal.com/)

### ⚙️ Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/ai-digital-forensics-assistant.git
cd ai-digital-forensics-assistant

# Install dependencies
pip install -r requirements.txt

# (Optional) Set your API Key
export VT_API_KEY="your_api_key_here"

# Run the app
streamlit run app.py
```

---

## 🧪 Screenshots & Diagrams
### 📁 File Metadata + VirusTotal Threat Report
![File Metadata Example](<Screenshot (196).png>)
---

### 📊 Log Anomaly Detection Output
![Log Anomaly Detection](<Screenshot (197).png>)
---

### 🗺️ EXIF Viewer with GPS Map
![EXIF Viewer](<Screenshot (198).png>)
![GPS map](<Screenshot (199).png>)

### 🎞️ Video Metadata Viewer
![Video Metadata Viewer](<Screenshot (200).png>)

---

## 📂 File Structure

📦 ai-digital-forensics-assistant/
│
├── src/
│   ├── file_analyzer.py
│   ├── ai_log_analyzer.py
│   ├── image_metadata.py
│   ├── video_metadata.py
│   └── virustotal_checker.py
│
├── gui/
│   └── app.py
├── requirements.txt
├── README.md
├── research_paper.pdf
└── screenshots/


---

## 🔐 VirusTotal Setup
1. Visit [VirusTotal API Key Page](https://www.virustotal.com/gui/user/apikey)
2. Copy your key and:
   - Paste it directly in `app.py` (not recommended), or
   - Export it as an environment variable:
     ```bash
     export VT_API_KEY="your_api_key"
     ```

---

## 📘 Example Use Case Logs

```log
[2025-05-10 10:05:44] 🔍 Analyzing SHA256: 3a5d...e2c
[2025-05-10 10:05:44] ✅ VirusTotal Report: Malicious = 4, Harmless = 65
[2025-05-10 10:05:55] 📊 Anomalies Detected: 3 rows flagged
[2025-05-10 10:06:22] 🗺️ GPS EXIF found. Map rendered at: 19.076, 72.877
[2025-05-10 10:06:55] 🎞️ Video analyzed: 1280x720, 30 FPS, duration 65s, Malicious = 1
```

---

## 🌐 Future Scope

- 🛡️ Real-time network traffic analysis  
- 📡 Cloud-sync evidence & reporting  
- 🧠 Add LLM-powered forensic report summaries  
- 📁 Support for Android/Windows image dumps
-🎤 Audio/video tampering detection via deep learning

---
## 🔗 Demo Video
Watch the full demo here: [https://youtu.be/zZeuESog7nQ]


## 📄 License

This project is released under the MIT License.

---

## 🙏 Acknowledgements

- [Streamlit](https://streamlit.io/)
- [VirusTotal API](https://www.virustotal.com/)
- [scikit-learn](https://scikit-learn.org/)
- [Folium](https://python-visualization.github.io/folium/)
- [OpenCV](https://opencv.org/)
