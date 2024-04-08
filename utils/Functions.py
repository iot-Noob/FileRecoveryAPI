from utils.ImportLib import  *
from config.Conf_Import import *
async def decode_jwt(token: str) -> dict:
    try:
        payload = decode(token, key, algorithms=[algo])
        return payload
    except Exception as e:
        logging.error("401 invalid jwt toekn canot decode")
        raise HTTPException(401, detail="Invalid JWT token")
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
 