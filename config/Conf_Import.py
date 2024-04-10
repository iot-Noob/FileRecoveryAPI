from utils.ImportLib import *
import re
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

