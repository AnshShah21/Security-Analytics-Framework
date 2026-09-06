import os
import hashlib
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
MAX_FILE_SIZE_MB = 100

UPLOAD_DIR = "pcaps"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def validate_and_store_pcap(file):
    """
    Validates uploaded PCAP file and stores it securely.
    Returns structured validation result.
    """

    if not file or file.filename == "":
        return {
            "status": "error",
            "message": "No file uploaded"
        }

    filename = secure_filename(file.filename)

    if not allowed_file(filename):
        return {
            "status": "invalid",
            "message": "Unsupported file type"
        }

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    save_path = os.path.join(UPLOAD_DIR, filename)

    file.save(save_path)

    file_size_mb = os.path.getsize(save_path) / (1024 * 1024)
    if file_size_mb > MAX_FILE_SIZE_MB:
        os.remove(save_path)
        return {
            "status": "invalid",
            "message": "File size exceeds allowed limit"
        }

    file_hash = calculate_sha256(save_path)

    return {
        "status": "valid",
        "pcap_name": filename,
        "hash": file_hash,
        "size_mb": round(file_size_mb, 2),
        "stored_path": save_path
    }
