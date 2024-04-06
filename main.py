import os
from fastapi import FastAPI,File,HTTPException,UploadFile,Query,Form,Depends 
from fastapi.responses import FileResponse,Response,HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
# from fs.osfs import OSFS
# from fs.ftpfs import FTPFS
# from ftplib import FTP_TLS
# from smb.SMBConnection import SMBConnection
import pydantic
from typing import List 
import psutil
import shutil
import jwt
from jwt import PyJWTError
from fastapi.security import HTTPBearer,OAuth2PasswordBearer
import toml
import datetime
import sqlite3
from createTable import create_tables,QueryRun
from pydantic import BaseModel,Field, EmailStr
import hashlib

### Security checkpoint
jetk=toml.load(r"./key.toml")

key=jetk['security-key']['JWT-KEY']
algo=jetk['security-key']['ALGORITHM']
security = HTTPBearer()
dp_paths=jetk['db-info']['db_path']
 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

### Implimentation

## FTP Login model
class FTP_Login(pydantic.BaseModel):
    server:str|None=None
    username:str
    password:str
    port:int=445

class UserSignup(BaseModel):
    username: str = Field(..., description="The username for the new user")
    password: str = Field(..., description="The password for the new user")
    email: EmailStr = Field(..., description="The email address for the new user")


app = FastAPI(title="File Recovery API ")

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    # Add more origins as needed
]

## Startup event 

def startup_event():
    print("API is starting...")
    create_tables(dp_paths)
    
    
@app.on_event("startup")
async def startup():
    startup_event()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
 
### Secure API

def hash_password(password):
    # You can choose a hashing algorithm here, like SHA-256
    return hashlib.sha256(password.encode()).hexdigest()
 

def authenticate_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, key, algorithms=[algo])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        # You can do further checks here, like checking if the user exists in the database
        return username
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
 


from fastapi import Form, HTTPException
import datetime
import jwt

@app.post("/token", tags=['Authentication'])
async def login_for_access_token(username: str = Form(...), password: str = Form(...)):
    # Hash the provided password
    hashed_password = hash_password(password)
    
    # Query the database to verify user
    query = "SELECT * FROM User WHERE username = ? AND password = ?"
    result = QueryRun(db=dp_paths, q=query, params=(username, hashed_password))
    
    if result:
        # Generate the access token
        access_token_expires = datetime.timedelta(minutes=30)
        to_encode = {"sub": username, "exp": datetime.datetime.utcnow() + access_token_expires}
        token = jwt.encode(to_encode, key, algorithm=algo)
        
        # Get the user ID
        quid = "SELECT id FROM User WHERE username=?"
        ap = (username,)
        cid_result = QueryRun(db=dp_paths, q=quid, params=ap)
        
        if cid_result:
            cid = cid_result[0][0]  # Extract user ID from the result
            
            # Check if the user ID exists in User_Token table
            check_token_query = "SELECT id FROM User_Token WHERE user_id = ?"
            check_token_result = QueryRun(db=dp_paths, q=check_token_query, params=(cid,))
            
            if check_token_result:
                # Update the token
                update_token_query = "UPDATE User_Token SET token = ? WHERE user_id = ?"
                update_token_values = (token, cid)
                QueryRun(db=dp_paths, q=update_token_query, params=update_token_values)
            else:
                # Insert a new token for the user
                insert_token_query = "INSERT INTO User_Token (user_id, token) VALUES (?, ?)"
                insert_token_values = (cid, token)
                QueryRun(db=dp_paths, q=insert_token_query, params=insert_token_values)
            
            return {"access_token": token, "token_type": "bearer"}
        else:
            raise HTTPException(status_code=500, detail="Failed to retrieve user ID")
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")




# Endpoint for user signup
 #test
@app.post("/signup", tags=["Authentication"], response_model=dict)
async def signup(user_info: UserSignup):
    # Hash the provided password before storing it
    hashed_password = hash_password(user_info.password)

    # Check if the username or email already exists in the database
    check_query = "SELECT * FROM User WHERE username = ? OR email = ?"
    check_result = QueryRun(dp_paths, check_query, (user_info.username, user_info.email))

    if check_result:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Insert the new user into the database
    insert_query = "INSERT INTO User (username, password, email, is_online) VALUES (?, ?, ?, ?)"
    insert_values = (user_info.username, hashed_password, user_info.email, False)
    QueryRun(dp_paths, insert_query, insert_values)

    # Get the ID of the newly inserted user
    get_user_id_query = "SELECT id FROM User WHERE username = ?"
    user_id_result = QueryRun(dp_paths, get_user_id_query, (user_info.username,))
    if user_id_result:
        user_id = user_id_result[0][0]
    else:
        raise HTTPException(status_code=500, detail="Failed to retrieve user ID after signup")

    # Update the token_id with the user's ID
    update_token_id_query = "UPDATE User SET token_id = ? WHERE id = ?"
    update_token_id_values = (user_id, user_id)
    QueryRun(dp_paths, update_token_id_query, update_token_id_values)

    return {"message": "User signed up successfully", "user_id": user_id}


## Update user
def get_db():
    return dp_paths 
@app.patch("/update-profile/{user_id}",tags=['Authentication'])
async def update_profile(
    user_id: int, 
    new_username: str = Form(None),
    new_password: str = Form(None),
    new_email: str = Form(None),
    db: sqlite3.Connection = Depends(get_db),
    token: str = Depends(oauth2_scheme)  # Use Depends to inject the database connection
):
    # Check if the user exists in the database
    user_query = "SELECT * FROM User WHERE id = ?"
    user_result = QueryRun(db, user_query, (user_id,))
    if not user_result:
        raise HTTPException(status_code=404, detail="User not found")

    # Update the user profile fields if new values are provided
    update_query = "UPDATE User SET"
    update_values = []

    if new_username:
        update_query += " username = ?,"
        update_values.append(new_username)

    if new_password:
        update_query += " password = ?,"
        update_values.append(new_password)

    if new_email:
        update_query += " email = ?,"
        update_values.append(new_email)

    # Remove the trailing comma from the update_query
    update_query = update_query.rstrip(",")

    # Add the WHERE clause to specify the user to update
    update_query += " WHERE id = ?"
    update_values.append(user_id)

    # Execute the update query
    QueryRun(db, update_query, update_values)

    return {"message": "User profile updated successfully"}

# Delete user
@app.delete("/delete-user/{user_id}", tags=['Authentication'])
async def delete_user(
    user_id: int,
    db: sqlite3.Connection = Depends(get_db),
    token: str = Depends(oauth2_scheme)
):
    # Check if the user exists in the database
    user_query = "SELECT * FROM User WHERE id = ?"
    user_result = QueryRun(db, user_query, (user_id,))
    if not user_result:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete the user from the database
    delete_query = "DELETE FROM User WHERE id = ?"
    QueryRun(db, delete_query, (user_id,))

    return {"message": "User deleted successfully"}
##BST for file 
 
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
### Access local using BST
@app.get("/local-file", tags=["Local-File"],name="Binary tree File system ",description="Won't accept Entire disk may stuck. \n\n Donot enter disk letter insted pass file path like d:/folder")
async def create_file_tree_endpoint(path: str,token: str = Depends(oauth2_scheme)):
    return await create_file_tree(path)

async def get_directory_structure(path):
    structure = {"name": os.path.basename(path)}
    try:
        if os.path.isdir(path):
            structure["children"] = [await get_directory_structure(os.path.join(path, child)) for child in os.listdir(path)]
        else:
            structure["children"] = []
    except PermissionError:
        structure["children"] = []
    return structure

@app.get("/local-simpSearch", tags=["Local-File"], description="Search file using Simple method")
async def search_simple(path: str = Query(...),token: str = Depends(oauth2_scheme)):
    if os.path.exists(path):
        return await get_directory_structure(path)
    else:
        raise HTTPException(404, f"File path doesn't exist: '{path}'")
     
### Download file
@app.get("/download-file/", tags=["Local-File"], name="Download File")
async def download_file(file_path: str,token: str = Depends(oauth2_scheme)):
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
async def get_dirs(token: str = Depends(oauth2_scheme) ):
    # Get a list of all disk partitions
    disk_partitions = psutil.disk_partitions()

    # Extract the disk names from the disk partitions
    disks = [partition.device for partition in disk_partitions]

    return {"Available disks": disks}

### Delete files 
@app.delete("/delete/{file_path:path}",tags=["Delete"],name="Delete files danger zone",description="Danger zone delete files -be careful -Once file deleted wont br recover")
async def delete_file_or_folder(file_path: str,token: str = Depends(oauth2_scheme)):
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
            return {"message": f"File '{file_path}' deleted successfully"}
        elif os.path.isdir(file_path):
            shutil.rmtree(file_path)
            return {"message": f"Folder '{file_path}' deleted successfully"}
        else:
            return {"error": f"'{file_path}' is neither a file nor a folder"}
    except Exception as e:
        return {"error": f"An error occurred: {e}"}
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

async def recover_files(drive: str, selected_formats: List[str], destination_folder: str,token: str = Depends(oauth2_scheme)):
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
    destination_folder: str = Form(...) ,
    token: str = Depends(oauth2_scheme)
):
    if not os.path.exists(destination_folder):
        os.mkdir(destination_folder)
        raise HTTPException(status_code=400, detail="Destination folder does not exist")
       
    recovered_files = await recover_files(drive, selected_formats, destination_folder)
    return {"recovered_files": recovered_files}

@app.get("/download-recovered-file/", tags=["Data Recovery"])
async def download_recovered_file(file_path: str,token: str = Depends(oauth2_scheme)):
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)