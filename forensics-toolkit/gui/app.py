import streamlit as st

# ✅ First Streamlit command
st.set_page_config(page_title="AI-Augmented Digital Forensics Assistant", layout="wide")

import sys
import os
import io
import pandas as pd
import folium
from streamlit_folium import st_folium

# Append root path to load from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Local imports
from src.file_analyzer import analyze_file_metadata
from src.ai_log_analyzer import detect_anomalies
from src.image_metadata import extract_image_metadata, extract_gps_location
from src.virustotal_checker import check_virustotal
from src.video_metadata import extract_video_metadata
from src.malware_detector import check_malware_virustotal

# VirusTotal API Key (load from env or hardcoded)
API_KEY = os.getenv("ca965dab669614e403701a67c6eda22e05cafaac4733f64cb59251723cb923da") or "ca965dab669614e403701a67c6eda22e05cafaac4733f64cb59251723cb923da"

st.title("🕵️ AI-Augmented Digital Forensics Assistant")

# Sidebar Navigation
menu = ["File Metadata", "Log Anomaly Detection", "Image EXIF Viewer", "Video Metadata"]
choice = st.sidebar.selectbox("📁 Select Analysis Module", menu)

# 1. File Metadata + Malware Scan
if choice == "File Metadata":
    uploaded_file = st.file_uploader("📄 Upload any file", type=None)
    if uploaded_file:
        with open("temp_upload.bin", "wb") as f:
            f.write(uploaded_file.read())

        meta = analyze_file_metadata("temp_upload.bin")
        st.subheader("📂 File Metadata")
        st.json(meta)

        if API_KEY:
            try:
                vt_result = check_malware_virustotal(API_KEY, "temp_upload.bin")
                if "error" in vt_result:
                    st.error(f"❌ VirusTotal Error: {vt_result['error']}")
                else:
                    st.subheader("🛡️ VirusTotal Threat Report")
                    st.json(vt_result)
            except Exception as e:
                st.error(f"⚠️ Error during VirusTotal check: {e}")
        else:
            st.warning("⚠️ Set your VirusTotal API key.")

# 2. Log Anomaly Detection
elif choice == "Log Anomaly Detection":
    uploaded_log = st.file_uploader("📝 Upload Log File (CSV)", type=["csv"])
    if uploaded_log:
        try:
            content = uploaded_log.getvalue().decode("utf-8")
        except UnicodeDecodeError:
            content = uploaded_log.getvalue().decode("latin1")

        df = pd.read_csv(io.StringIO(content))
        st.subheader("📋 Raw Log Preview")
        st.dataframe(df.head())

        try:
            anomalies = detect_anomalies(uploaded_log)
            st.subheader("🚨 Detected Anomalies")
            st.dataframe(anomalies)
        except Exception as e:
            st.error(f"⚠️ Anomaly detection failed: {e}")

# 3. Image EXIF Viewer + GPS
elif choice == "Image EXIF Viewer":
    uploaded_img = st.file_uploader("🖼️ Upload JPG Image", type=["jpg", "jpeg"])
    if uploaded_img:
        with open("temp_img.jpg", "wb") as f:
            f.write(uploaded_img.read())

        meta = extract_image_metadata("temp_img.jpg")
        st.subheader("🧾 EXIF Metadata")
        st.json(meta)

        gps_coords = extract_gps_location(meta)
        if gps_coords:
            st.success(f"📍 GPS Location: {gps_coords}")
            map_ = folium.Map(location=gps_coords, zoom_start=12)
            folium.Marker(location=gps_coords, popup="📸 Image Taken Here").add_to(map_)
            st_folium(map_, width=700, height=500)
        else:
            st.warning("⚠️ No GPS data found in EXIF.")

# 4. Video Metadata + Malware Scan
elif choice == "Video Metadata":
    uploaded_vid = st.file_uploader("🎥 Upload Video File", type=["mp4", "mov", "avi"])
    if uploaded_vid:
        with open("temp_video.mp4", "wb") as f:
            f.write(uploaded_vid.read())

        st.subheader("🎞️ Extracted Video Metadata")
        try:
            vid_meta = extract_video_metadata("temp_video.mp4")
            st.json(vid_meta)

            if API_KEY:
                vt_result = check_malware_virustotal(API_KEY, "temp_video.mp4")
                if "error" not in vt_result:
                    st.subheader("🛡️ VirusTotal Threat Report (Video)")
                    st.json(vt_result)
                else:
                    st.error(f"❌ VirusTotal Error: {vt_result['error']}")
        except Exception as e:
            st.error(f"⚠️ Error reading video metadata: {e}")
