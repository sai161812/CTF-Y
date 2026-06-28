"""
modules/forensics.py
--------------------
File analysis, steganography detection, metadata extraction, and binary inspection.
"""

import os
import struct
import string
from pathlib import Path
from tools.runner import run_cmd, tool_available


# ──────────────────────────────────────────────────────────────────────────────
# File identification
# ──────────────────────────────────────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff":       "JPEG image",
    b"GIF8":               "GIF image",
    b"PK\x03\x04":         "ZIP archive",
    b"PK\x05\x06":         "ZIP archive (empty)",
    b"\x1f\x8b":           "GZIP compressed",
    b"BZh":                "BZIP2 compressed",
    b"\xfd7zXZ":           "XZ compressed",
    b"7z\xbc\xaf'\"":      "7-Zip archive",
    b"Rar!":               "RAR archive",
    b"\x7fELF":            "ELF executable",
    b"MZ":                 "Windows PE executable",
    b"%PDF":               "PDF document",
    b"OggS":               "OGG audio",
    b"ID3":                "MP3 audio",
    b"RIFF":               "WAV / AVI",
    b"\x00\x00\x00\x18ftypmp4": "MP4 video",
    b"SQLite format 3":    "SQLite database",
}


def detect_magic(filepath: str) -> str:
    """Read first 32 bytes and match against known magic numbers."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
        for magic, label in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                return label
        return f"Unknown (header: {header[:16].hex()})"
    except Exception as e:
        return f"Error: {e}"


def file_info(filepath: str) -> dict:
    """Comprehensive file info: type, size, magic, hashes."""
    import hashlib
    path = Path(filepath)
    info = {
        "path": str(path.resolve()),
        "name": path.name,
        "size": path.stat().st_size if path.exists() else 0,
        "magic_type": detect_magic(filepath),
        "file_cmd": "",
        "md5": "",
        "sha256": "",
    }
    # file command
    r = run_cmd(f"file {filepath}")
    info["file_cmd"] = r["stdout"].strip()

    # hashes
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        info["md5"] = hashlib.md5(data).hexdigest()
        info["sha256"] = hashlib.sha256(data).hexdigest()
    except Exception:
        pass

    return info


# ──────────────────────────────────────────────────────────────────────────────
# String extraction
# ──────────────────────────────────────────────────────────────────────────────

def extract_strings(filepath: str, min_len: int = 4) -> list[str]:
    """Extract printable strings from binary file."""
    r = run_cmd(f"strings -n {min_len} {filepath}")
    if r["error"]:
        # Fallback: pure Python
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            printable = set(string.printable.encode())
            current = []
            results = []
            for byte in data:
                if byte in printable:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_len:
                        results.append("".join(current))
                    current = []
            if len(current) >= min_len:
                results.append("".join(current))
            return results
        except Exception:
            return []
    return [s for s in r["stdout"].splitlines() if len(s) >= min_len]


# ──────────────────────────────────────────────────────────────────────────────
# Metadata
# ──────────────────────────────────────────────────────────────────────────────

def extract_metadata(filepath: str) -> dict:
    """Extract EXIF and other metadata using exiftool."""
    r = run_cmd(f"exiftool {filepath}")
    meta = {}
    for line in r["stdout"].splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta


def extract_metadata_python(filepath: str) -> dict:
    """Fallback: PIL-based metadata for images."""
    meta = {}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(filepath)
        meta["format"] = img.format
        meta["size"] = img.size
        meta["mode"] = img.mode
        raw_exif = img._getexif() if hasattr(img, "_getexif") else None
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag = TAGS.get(tag_id, tag_id)
                meta[str(tag)] = str(value)
    except Exception as e:
        meta["error"] = str(e)
    return meta


# ──────────────────────────────────────────────────────────────────────────────
# Hex / Binary inspection
# ──────────────────────────────────────────────────────────────────────────────

def hexdump(filepath: str, num_bytes: int = 512) -> str:
    """Return hex dump of first N bytes."""
    r = run_cmd(f"xxd {filepath}")
    if not r["error"]:
        lines = r["stdout"].splitlines()
        return "\n".join(lines[: num_bytes // 16])
    # Fallback
    try:
        with open(filepath, "rb") as f:
            data = f.read(num_bytes)
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i: i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


def find_embedded_files(filepath: str) -> str:
    """Use binwalk to scan for embedded files."""
    if tool_available("binwalk"):
        r = run_cmd(f"binwalk {filepath}")
        return r["stdout"]
    return "binwalk not installed"


def binwalk_extract(filepath: str, output_dir: str = "/tmp/binwalk_out") -> str:
    """Extract embedded files with binwalk."""
    os.makedirs(output_dir, exist_ok=True)
    r = run_cmd(f"binwalk -e --directory {output_dir} {filepath}", timeout=60)
    if r["error"]:
        return f"Error: {r['error']}"
    extracted = list(Path(output_dir).rglob("*"))
    return f"Extracted {len(extracted)} files to {output_dir}:\n" + "\n".join(str(p) for p in extracted[:20])


# ──────────────────────────────────────────────────────────────────────────────
# PNG analysis
# ──────────────────────────────────────────────────────────────────────────────

def parse_png_chunks(filepath: str) -> list[dict]:
    """Manually parse PNG chunks — can reveal hidden tEXt, iTXt, zTXt chunks."""
    chunks = []
    try:
        with open(filepath, "rb") as f:
            sig = f.read(8)
            if sig != b"\x89PNG\r\n\x1a\n":
                return [{"error": "Not a valid PNG"}]
            while True:
                length_bytes = f.read(4)
                if not length_bytes or len(length_bytes) < 4:
                    break
                length = struct.unpack(">I", length_bytes)[0]
                chunk_type = f.read(4).decode("ascii", errors="replace")
                data = f.read(length)
                _ = f.read(4)  # CRC
                chunk = {"type": chunk_type, "length": length}
                if chunk_type in ("tEXt", "iTXt", "zTXt", "eXIf"):
                    try:
                        chunk["data"] = data.decode("utf-8", errors="replace")
                    except Exception:
                        chunk["data"] = data.hex()
                chunks.append(chunk)
    except Exception as e:
        chunks.append({"error": str(e)})
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Steganography
# ──────────────────────────────────────────────────────────────────────────────

def zsteg_scan(filepath: str) -> str:
    """Run zsteg on PNG/BMP to detect LSB steganography."""
    if tool_available("zsteg"):
        r = run_cmd(f"zsteg {filepath}", timeout=30)
        return r["stdout"] or r["stderr"]
    return "zsteg not installed (gem install zsteg)"


def steghide_extract(filepath: str, passphrase: str = "",
                     output: str = "/tmp/steg_out.txt") -> str:
    """Try to extract steghide payload."""
    if not tool_available("steghide"):
        return "steghide not installed"
    cmd = f"steghide extract -sf {filepath} -p '{passphrase}' -xf {output} -f"
    r = run_cmd(cmd)
    if "wrote extracted" in (r["stdout"] + r["stderr"]).lower():
        try:
            with open(output) as f:
                return f.read()
        except Exception:
            pass
    return r["stdout"] + r["stderr"]


def lsb_extract_python(filepath: str, num_pixels: int = 2000) -> str:
    """
    Pure-Python LSB extraction from RGB channels.
    Reads the least-significant bit of each channel in order.
    """
    try:
        from PIL import Image
        img = Image.open(filepath).convert("RGB")
        pixels = list(img.getdata())[:num_pixels]
        bits = ""
        for r, g, b in pixels:
            bits += str(r & 1) + str(g & 1) + str(b & 1)
        chars = []
        for i in range(0, len(bits) - 7, 8):
            val = int(bits[i: i + 8], 2)
            if 32 <= val < 127:
                chars.append(chr(val))
            else:
                chars.append("·")
        return "".join(chars[:200])
    except Exception as e:
        return f"Error: {e}"


def stegsolve_planes(filepath: str, output_dir: str = "/tmp/planes") -> str:
    """
    Extract individual bit planes from an image and save them.
    Equivalent of StegSolve bit-plane analysis.
    """
    try:
        from PIL import Image
        import os
        img = Image.open(filepath).convert("RGB")
        width, height = img.size
        os.makedirs(output_dir, exist_ok=True)
        saved = []
        for channel, name in enumerate(["R", "G", "B"]):
            for bit in range(8):
                plane = Image.new("L", (width, height))
                pixels = []
                for pixel in img.getdata():
                    pixels.append(255 if (pixel[channel] >> bit) & 1 else 0)
                plane.putdata(pixels)
                out_path = os.path.join(output_dir, f"{name}_bit{bit}.png")
                plane.save(out_path)
                saved.append(out_path)
        return f"Saved {len(saved)} plane images to {output_dir}"
    except Exception as e:
        return f"Error: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# Audio steganography
# ──────────────────────────────────────────────────────────────────────────────

def spectrogram_screenshot(filepath: str, output: str = "/tmp/spectrogram.png") -> str:
    """Generate spectrogram from audio file using sox."""
    if tool_available("sox"):
        r = run_cmd(f"sox {filepath} -n spectrogram -o {output}")
        if not r["error"]:
            return f"Spectrogram saved to {output}"
        return r["stderr"]
    return "sox not installed"


def wavsteg_extract(filepath: str) -> str:
    """Try WavSteg-style LSB extraction from WAV."""
    try:
        import wave
        with wave.open(filepath, "rb") as w:
            frames = w.readframes(w.getnframes())
        bits = ""
        for byte in frames[:8000]:
            bits += str(byte & 1)
        chars = []
        for i in range(0, len(bits) - 7, 8):
            val = int(bits[i: i + 8], 2)
            if 32 <= val < 127:
                chars.append(chr(val))
        return "".join(chars[:200])
    except Exception as e:
        return f"Error: {e}"


# ──────────────────────────────────────────────────────────────────────────────
# Archive / compression
# ──────────────────────────────────────────────────────────────────────────────

def list_zip(filepath: str) -> str:
    r = run_cmd(f"unzip -l {filepath}")
    return r["stdout"] or r["stderr"]


def crack_zip_password(filepath: str, wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """Use fcrackzip or john to crack password-protected zip."""
    if tool_available("fcrackzip"):
        r = run_cmd(f"fcrackzip -u -D -p {wordlist} {filepath}", timeout=120)
        return r["stdout"] + r["stderr"]
    return "fcrackzip not installed"


# ──────────────────────────────────────────────────────────────────────────────
# Network / PCAP
# ──────────────────────────────────────────────────────────────────────────────

def pcap_summary(filepath: str) -> str:
    if tool_available("tshark"):
        r = run_cmd(f"tshark -r {filepath} -q -z io,stat,0", timeout=30)
        return r["stdout"][:3000]
    return "tshark not installed"


def pcap_strings(filepath: str) -> str:
    if tool_available("tshark"):
        r = run_cmd(
            f"tshark -r {filepath} -T fields -e data.text -Y 'data.text'",
            timeout=30,
        )
        return r["stdout"][:3000]
    return extract_strings(filepath)


def pcap_http(filepath: str) -> str:
    """Extract HTTP requests/responses from PCAP."""
    if tool_available("tshark"):
        r = run_cmd(
            f"tshark -r {filepath} -Y http -T fields "
            f"-e http.request.full_uri -e http.response.code -e http.file_data",
            timeout=30,
        )
        return r["stdout"][:3000]
    return "tshark not installed"


# ──────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ──────────────────────────────────────────────────────────────────────────────

def auto_analyze(filepath: str) -> dict:
    """
    Perform a full automatic analysis of a file and return a summary dict.
    This is the entry point the agent calls first for any forensics challenge.
    """
    info = file_info(filepath)
    result = {"file_info": info, "steps": []}

    ftype = (info.get("magic_type", "") + " " + info.get("file_cmd", "")).lower()

    # Strings always
    strs = extract_strings(filepath)
    result["strings_sample"] = strs[:50]
    result["steps"].append("extracted_strings")

    # PNG-specific
    if "png" in ftype:
        result["png_chunks"] = parse_png_chunks(filepath)
        result["lsb"] = lsb_extract_python(filepath)
        result["zsteg"] = zsteg_scan(filepath)
        result["steps"].extend(["png_chunks", "lsb", "zsteg"])

    # JPEG-specific
    elif "jpeg" in ftype or "jpg" in ftype:
        result["metadata"] = extract_metadata(filepath)
        result["steghide"] = steghide_extract(filepath)
        result["steps"].extend(["metadata", "steghide"])

    # Audio
    elif "wav" in ftype or "audio" in ftype:
        result["wav_lsb"] = wavsteg_extract(filepath)
        result["spectrogram"] = spectrogram_screenshot(filepath)
        result["steps"].extend(["wav_lsb", "spectrogram"])

    # ZIP / archives
    elif "zip" in ftype or "archive" in ftype:
        result["zip_listing"] = list_zip(filepath)
        result["steps"].append("zip_listing")

    # PCAP
    elif "pcap" in ftype or "capture" in ftype:
        result["pcap_summary"] = pcap_summary(filepath)
        result["pcap_http"] = pcap_http(filepath)
        result["pcap_strings"] = pcap_strings(filepath)
        result["steps"].extend(["pcap_summary", "pcap_http", "pcap_strings"])

    # Generic binary
    else:
        result["hexdump"] = hexdump(filepath, num_bytes=256)
        result["binwalk"] = find_embedded_files(filepath)
        result["metadata"] = extract_metadata(filepath)
        result["steps"].extend(["hexdump", "binwalk", "metadata"])

    return result