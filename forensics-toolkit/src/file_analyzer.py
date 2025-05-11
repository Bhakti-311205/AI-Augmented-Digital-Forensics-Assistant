import os
import hashlib
import magic
from datetime import datetime

def analyze_file_metadata(file_path):
    stats = os.stat(file_path)
    metadata = {
        "File Name": os.path.basename(file_path),
        "Size (Bytes)": stats.st_size,
        "Last Modified": datetime.fromtimestamp(stats.st_mtime),
        "Created": datetime.fromtimestamp(stats.st_ctime),
        "File Type": magic.from_file(file_path, mime=True),
        "MD5 Hash": hashlib.md5(open(file_path, 'rb').read()).hexdigest(),
        "SHA256 Hash": hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
    }
    return metadata
