import requests
import time

def check_virustotal(api_key, sha256_hash, file_path=None):
    headers = {
        "x-apikey": api_key
    }

    # First: try fetching report by hash
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "Malicious": stats.get("malicious", 0),
            "Suspicious": stats.get("suspicious", 0),
            "Harmless": stats.get("harmless", 0),
            "Undetected": stats.get("undetected", 0),
            "source": "hash_lookup"
        }

    # If not found, upload the file
    elif response.status_code == 404 and file_path:
        upload_url = "https://www.virustotal.com/api/v3/files"
        with open(file_path, "rb") as f:
            files = {"file": (file_path, f)}
            upload_response = requests.post(upload_url, headers=headers, files=files)

        if upload_response.status_code == 200:
            analysis_id = upload_response.json()["data"]["id"]

            # Poll for results
            for _ in range(10):
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                result_response = requests.get(result_url, headers=headers)
                result_json = result_response.json()
                status = result_json["data"]["attributes"]["status"]
                if status == "completed":
                    stats = result_json["data"]["attributes"]["stats"]
                    return {
                        "Malicious": stats.get("malicious", 0),
                        "Suspicious": stats.get("suspicious", 0),
                        "Harmless": stats.get("harmless", 0),
                        "Undetected": stats.get("undetected", 0),
                        "source": "upload_scan"
                    }
                time.sleep(2)
            return {"error": "Analysis took too long or failed."}
        else:
            return {"error": f"Upload failed: {upload_response.status_code}"}
    else:
        return {"error": f"Hash lookup failed: {response.status_code}"}
