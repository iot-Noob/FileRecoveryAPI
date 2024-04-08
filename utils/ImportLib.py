import os
from fastapi import FastAPI,File,HTTPException,UploadFile,Query,Form,Depends ,Form, HTTPException,Path
from fastapi.responses import FileResponse,Response,HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
# from fs.osfs import OSFS
# from fs.ftpfs import FTPFS
# from ftplib import FTP_TLS
# from smb.SMBConnection import SMBConnection
import pydantic
from typing import List ,Optional
import psutil
import shutil
import jwt
from jwt import decode
from jwt import PyJWTError
from fastapi.security import HTTPBearer,OAuth2PasswordBearer
import toml
import sqlite3
from createTable import create_tables,QueryRun,QueryRun_Single
from pydantic import BaseModel,Field, EmailStr
import hashlib
import datetime
import logging 
