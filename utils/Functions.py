from utils.ImportLib import  *
from config.Conf_Import import *
async def decode_jwt(token: str) -> dict:
    try:
        payload = decode(token, key, algorithms=[algo])
        return payload
    except Exception as e:
        logging.error("401 invalid jwt toekn canot decode",e)
        raise HTTPException(401, detail=f"Invalid JWT token")
### Secure API
 
def hash_password(password):
    # You can choose a hashing algorithm here, like SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

async def is_token_valid_v2(token: str = Depends(security)):
    try:
        payload = jwt.decode(token.credentials, key, algorithms=[algo])
        expiration_time = datetime.datetime.fromtimestamp(payload['exp'], datetime.timezone.utc)
        if expiration_time > datetime.datetime.now(datetime.timezone.utc):
            # Check if the user exists in the database or perform any other necessary checks
            username: str = payload.get("sub")
            if username is None:
                logging.error("Invalid token  while validating")
                raise HTTPException(status_code=401, detail="Invalid token")
            # Additional checks if needed
            # ...
            return  token.credentials 
        else:
            logging.error("User token expire.")
            raise HTTPException(status_code=401, detail="Token has expired")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
 
 
### Login
def get_db():
    return dp_paths 
async def get_directory_structure(path: str, blist: List[str] = None, wlist: List[str] = None):
    logging.debug(f"Processing directory: {path}")
    structure = {"name": os.path.basename(path)}
    try:
        structure["children"] = []
        for child in os.listdir(path):
            child_path = os.path.join(path, child)
            logging.debug(f"Checking child: {child}")
            included_by_whitelist = False
            if wlist:
                for pattern in wlist:
                    if pattern.startswith("."):
                        if child.endswith(pattern):
                            included_by_whitelist = True
                            break
                    elif pattern in child:
                        included_by_whitelist = True
                        break
            
            if included_by_whitelist:
                logging.debug(f"Included by whitelist: {child}")
                logging.debug(f"Appending child: {child}")
                child_structure = await get_directory_structure(child_path, blist, wlist)
                if child_structure is not None:
                    structure["children"].append(child_structure)
            else:
                included_by_blacklist = False
                if blist:
                    for pattern in blist:
                        if pattern.startswith("."):
                            if child.endswith(pattern):
                                included_by_blacklist = True
                                break
                        elif pattern in child:
                            included_by_blacklist = True
                            break
                
                if not included_by_blacklist:
                    logging.debug(f"Appending child: {child}")
                    child_structure = await get_directory_structure(child_path, blist, wlist)
                    if child_structure is not None:
                        structure["children"].append(child_structure)
                else:
                    logging.debug(f"Skipping child due to blacklist: {child}")
    except Exception as e:
        logging.error(f"Error processing directory {path}: {e}")
        # Log the error but continue processing other files and directories
    return structure

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

class TreeNode:
    def __init__(self, name):
        self.name = name
        self.children = []
async def create_file_tree(path: str, blist: list, wlist: list):
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
                # Extract the file extension
                _, ext = os.path.splitext(file)
                # Check if the file or its extension is in the whitelist or not in the blacklist before adding
                if (any(re.match(pattern, file) for pattern in wlist) or any(re.match(pattern, ext) for pattern in wlist)) or (not any(re.match(pattern, file) for pattern in blist) and not any(re.match(pattern, ext) for pattern in blist)):
                    current_node.children.append(TreeNode(file))
    else:
        logging.error("BST Error cannot detect file.")
        raise HTTPException(500, "Cannot detect file error")
    return root
async def extract_path(query)->list:
    try:
        extracted_queries = []
        for q in query:
            
            extracted_queries.append(q[3])
        return extracted_queries
    except Exception as e:
        raise HTTPException(405, f"Cannot extract queries: {e}")
             