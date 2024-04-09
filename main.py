from utils.ImportLib import  *
from config.Conf_Import import *
from routes.Routes import BasicRouter
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')
### Start of Fastapi
"""
Read: Allows users to view the contents of the file.

Write: Allows users to modify the contents of the file.

Execute: Allows users to execute the file, which might be relevant for executable files or scripts.

Delete: Allows users to delete the file.

Create: Allows users to create new files within the directory.

Modify permissions: Allows users to change the permissions of the file (grant or revoke access to other users).

Share: Allows users to share the file with other users.

Download: Allows users to download the file from the server.

Upload: Allows users to upload new files to the server.

Move: Allows users to move the file to a different directory.
"""
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
    
    # Set up logging
    tf = os.path.split(lfp)[0]
    if not os.path.exists(tf):
        os.makedirs(tf)
    
    logging.basicConfig(
        filename=os.path.join(tf, 'app.log'),  # Set the log file in the created directory
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logging.info("API startup complete.")
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

app.include_router(BasicRouter)

