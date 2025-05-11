import os
import cv2
import hashlib
import requests

# Replace this with your actual VirusTotal API key
VIRUSTOTAL_API_KEY = "ca965dab669614e403701a67c6eda22e05cafaac4733f64cb59251723cb923da"

def extract_video_metadata(file_path):
    if not os.path.exists(file_path):
        return {"error": "File not found."}
    
    try:
        cap = cv2.VideoCapture(file_path)
        if not cap.isOpened():
            return {"error": "Could not open video file."}

        fps = cap.get(cv2.CAP_PROP_FPS)
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        duration = int(frame_count / fps) if fps > 0 else 0
        codec = int(cap.get(cv2.CAP_PROP_FOURCC))

        cap.release()

        metadata = {
            "filename": os.path.basename(file_path),
            "frame_count": frame_count,
            "fps": fps,
            "resolution": f"{width}x{height}",
            "duration_seconds": duration,
            "codec": codec
        }

        # Attach VirusTotal report
        metadata["virustotal_report"] = get_virustotal_report(file_path)
        return metadata

    except Exception as e:
        return {"error": f"OpenCV failed: {str(e)}"}


def get_virustotal_report(file_path):
    try:
        file_hash = compute_sha256(file_path)
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious_count = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            return {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        else:
            return {"status": "Not found in VirusTotal", "code": response.status_code}
    except Exception as e:
        return {"error": str(e)}

def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()
