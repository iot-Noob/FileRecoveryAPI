from pydantic import BaseModel
from utils.ImportLib import *
## FTP Login model

class FTP_Login(BaseModel):
    server:str|None=None
    username:str
    password:str
    port:int=445

class UserSignup(BaseModel):
    username: str = Field(..., description="The username for the new user")
    password: str = Field(..., description="The password for the new user")
    email: EmailStr = Field(..., description="The email address for the new user")