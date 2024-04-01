import os
from fastapi import FastAPI,File,HTTPException,UploadFile,Query,Form
from fastapi.responses import FileResponse,Response,HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
# from fs.osfs import OSFS
# from fs.ftpfs import FTPFS
# from ftplib import FTP_TLS
# from smb.SMBConnection import SMBConnection
import pydantic
from typing import List 
import psutil
 


class FTP_Login(pydantic.BaseModel):
    server:str|None=None
    username:str
    password:str
    port:int=445

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    # Add more origins as needed
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

## Make binary tree

class TreeNode:
    def __init__(self, name):
        self.name = name
        self.children = []
 
async def create_file_tree(path: str):
    root = TreeNode(path)
    if os.path.exists(path):
        for root_dir, folders, files in os.walk(path):
            current_node = root
            # Split the path to get each directory level
            dirs = root_dir.split(os.sep)[1:]
            for d in dirs:
                found = False
                # Check if the directory already exists as a child
                for child in current_node.children:
                    if child.name == d:
                        current_node = child
                        found = True
                        break
                # If not found, create a new node
                if not found:
                    new_node = TreeNode(d)
                    current_node.children.append(new_node)
                    current_node = new_node
            # Add files as children of the leaf node
            for file in files:
                current_node.children.append(TreeNode(file))
    else:
        raise HTTPException(500, "Cannot detect file error")
    return root

 

@app.get("/local-file", tags=["Local-File"],name="Binary tree File system ",description="Won't accept Entire disk may stuck. \n\n Donot enter disk letter insted pass file path like d:/folder")
async def create_file_tree_endpoint(path: str):
    return await create_file_tree(path)

 

### Download file
@app.get("/download-file/", tags=["Local-File"], name="Download File")
async def download_file(file_path: str):
    """
    Download a file from the binary tree file system.

    :param file_path: The path to the file relative to the root of the file system.
    """
    # Check if the file path exists in the file system
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Return the file as a response
    return  Response(file_path)
## List local dirs

@app.get("/list_dirs", tags=["Local-File"],name="Directory List") 
async def get_dirs():
    # Get a list of all disk partitions
    disk_partitions = psutil.disk_partitions()

    # Extract the disk names from the disk partitions
    disks = [partition.device for partition in disk_partitions]

    return {"Available disks": disks}
    
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

async def recover_files(drive: str, selected_formats: List[str], destination_folder: str):
    fileD = open(drive, "rb")
    size = 512              # Size of bytes to read
    offs = 0                # Offset location
    rcvd = 0                # Recovered file ID
    
    recovered_files = []
    
    try:
        while True:
            byte = fileD.read(size)
            if not byte:
                break
            
            for extension, header in header_files.items():
                if extension in selected_formats:
                    found = byte.find(bytes.fromhex(header))
                    if found >= 0:
                        filename = f"{rcvd}_{extension}.jpg"
                        filepath = os.path.join(destination_folder, filename)
                        with open(filepath, "wb") as fileN:
                            fileN.write(byte[found:])
                            
                            while True:
                                byte = fileD.read(size)
                                bfind = byte.find(b'\xff\xd9')
                                if bfind >= 0:
                                    fileN.write(byte[:bfind+2])
                                    recovered_files.append(filepath)
                                    break
                                else:
                                    fileN.write(byte)
                                    
                        rcvd += 1
                    
    finally:
        fileD.close()
    
    return recovered_files

@app.post("/recover-files/", tags=["Data Recovery"])
async def recover_files_endpoint(
    drive: str = Form(...),
    selected_formats: List[str] = Form(...),
    destination_folder: str = Form(...),
):
    if not os.path.exists(destination_folder):
        os.mkdir(destination_folder)
        raise HTTPException(status_code=400, detail="Destination folder does not exist")
       
    recovered_files = await recover_files(drive, selected_formats, destination_folder)
    return {"recovered_files": recovered_files}

@app.get("/download-recovered-file/", tags=["Data Recovery"])
async def download_recovered_file(file_path: str):
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)