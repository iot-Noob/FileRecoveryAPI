from utils.ImportLib import *
tc = 0
for root, _, files in os.walk(r"./"):
    for f in files:
        if f.endswith(".toml"):
            tc += 1

if not os.path.exists("key.toml"):
    logging.error("Error: key.toml not found in directory.")
    raise FileNotFoundError("key.toml not found")

# Load the key.toml file if it exists
jetk = toml.load("key.toml")

# Continue with the rest of the script
key = jetk['security-key']['JWT-KEY']


key=jetk['security-key']['JWT-KEY']
algo=jetk['security-key']['ALGORITHM']
security = HTTPBearer()
dp_paths=jetk['db-info']['db_path']
lfp=jetk['logging']['path']

###RECOVER FILES
header_files = {
    # Image formats
    ".jpg": b"\xff\xd8\xff",   # JPEG
    ".png": b"\x89\x50\x4e\x47",   # PNG
    ".gif": b"\x47\x49\x46\x38",   # GIF
    ".tiff": b"\x49\x49\x2a\x00",  # TIFF
    ".bmp": b"\x42\x4d",       # BMP
    # Document formats
    ".pdf": b"\x25\x50\x44\x46",   # PDF
    ".doc": b"\xd0\xcf\x11\xe0",   # Microsoft Office files (DOC, XLS, PPT)
    ".zip": b"\x50\x4b\x03\x04",   # ZIP
    ".rar": b"\x52\x61\x72\x21",   # RAR
    # CAD formats
    ".dwg": b"\x41\x43\x31\x30",   # DWG
    ".dxf": b"\x47\x49\x46\x38",   # DXF
    # Audio formats
    ".mp3": b"\x49\x44\x33",     # MP3
    ".flac": b"\x66\x4c\x61\x43",  # FLAC
    ".midi": b"\x4d\x54\x68\x64",  # MIDI
    ".wav": b"\x52\x49\x46\x46",   # WAV
    # Video formats
    ".mpeg": b"\x00\x00\x01\xba",  # MPEG
    # Blender (.blend) and Wavefront Object (.obj)
    ".blend": b"\x42\x4c\x45\x4e\x44",  # BLEND
    ".obj": b"\x6f\x62\x6a\x20",   # OBJ
    # Add more headers for other file formats as needed
}