from utils.ImportLib import  *
from config.Conf_Import import *
from routes.Routes import BasicRouter
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

### Implimentation



### Start of Fastapi

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