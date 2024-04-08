from fastapi import APIRouter
from utils.ImportLib import *
from models.Model import *
from utils.Functions import *
BasicRouter=APIRouter()

@BasicRouter.post("/Login", tags=['Authentication'],name="Login Account",description="Login to get token")
async def login_for_access_token(username: str = Form(...), password: str = Form(...)):
    # Hash the provided password
    hashed_password = hash_password(password)
    
    # Query the database to verify user
    query = "SELECT * FROM User WHERE username = ? AND password = ?"
    result = QueryRun(db=dp_paths, q=query, params=(username, hashed_password))
    
    if result:
        # Extract user ID from the database result
        user_id = result[0][0]

        # Generate the access token
        access_token_expires = datetime.timedelta(minutes=30)
        to_encode = {"sub": username, "id": user_id, "exp": datetime.datetime.now(datetime.timezone.utc) + access_token_expires}
        token = jwt.encode(to_encode, key, algorithm=algo)
        
        # Check if the user ID exists in User_Token table
        check_token_query = "SELECT id FROM User_Token WHERE user_id = ?"
        check_token_result = QueryRun(db=dp_paths, q=check_token_query, params=(user_id,))
        
        if check_token_result:
            # Update the token
            update_token_query = "UPDATE User_Token SET token = ? WHERE user_id = ?"
            update_token_values = (token, user_id)
            QueryRun(db=dp_paths, q=update_token_query, params=update_token_values)
        else:
            # Insert a new token for the user
            insert_token_query = "INSERT INTO User_Token (user_id, token) VALUES (?, ?)"
            insert_token_values = (user_id, token)
            QueryRun(db=dp_paths, q=insert_token_query, params=insert_token_values)
        logging.info(f"user login sucess...  ")
        return {"access_token": token, "token_type": "bearer"}
    else:
        logging.error("incorrect username password canot login.")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
# Endpoint for user signup
@BasicRouter.post("/signup", tags=["Authentication"], response_model=dict)
async def signup(user_info: UserSignup):
    # Hash the provided password before storing it
    hashed_password = hash_password(user_info.password)

    # Check if the username or email already exists in the database
    check_query = "SELECT * FROM User WHERE username = ? OR email = ?"
    check_result = QueryRun(dp_paths, check_query, (user_info.username, user_info.email))

    if check_result:
        logging.warning("SIGN UP Error: Error  username or password already exist.")
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Insert the new user into the database
    insert_query = "INSERT INTO User (username, password, email, is_online,user_role) VALUES (?, ?, ?, ?,?)"
    insert_values = (user_info.username, hashed_password, user_info.email, False,"user")
    QueryRun(dp_paths, insert_query, insert_values)

    # Get the ID of the newly inserted user
    get_user_id_query = "SELECT id FROM User WHERE username = ?"
    user_id_result = QueryRun(dp_paths, get_user_id_query, (user_info.username,))
    if user_id_result:
        user_id = user_id_result[0][0]
    else:
        logging.error("Failed to retrieve user ID after signup")
        raise HTTPException(status_code=500, detail="Failed to retrieve user ID after signup")

    # Update the token_id with the user's ID
    update_token_id_query = "UPDATE User SET token_id = ? WHERE id = ?"
    update_token_id_values = (user_id, user_id)
    QueryRun(dp_paths, update_token_id_query, update_token_id_values)
    logging.info("Sign up sucess.")
    return {"message": "User signed up successfully", "user_id": user_id}


## Update user
@BasicRouter.patch("/update-profile/{user_id}", tags=['Authentication'])
async def update_profile(
    user_id: int,
    new_username: Optional[str] = Form(None),
    new_password: Optional[str] = Form(None),
    new_email: Optional[str] = Form(None),
    role: Optional[str] = Form(None),
    db: sqlite3.Connection = Depends(get_db),
    token: str = Depends(is_token_valid_v2)
):  
    dec_tok = await decode_jwt(token=token)
    uid = dec_tok['id']
    user_role = QueryRun_Single(db, "SELECT user_role FROM User WHERE id = ?", (uid,))
    
    if user_role is None:
        logging.warning("User not found fail to update user.")
        raise HTTPException(status_code=404, detail="User not found")

    # Check if the user is an admin
    if user_role[0] == 'admin':
        # Admin can update user profiles and roles
        # If user_id is provided, update the profile and role of that user
        if user_id:
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

            if role:
                update_query += " user_role = ?,"
                update_values.append(role)

            # Remove the trailing comma from the update_query
            update_query = update_query.rstrip(",")

            # Add the WHERE clause to specify the user to update
            update_query += " WHERE id = ?"
            update_values.append(user_id)

            # Execute the update query
            QueryRun(db, update_query, update_values)
            logging.info("Profile upload sucess")
            return {"message": f"User profile and role updated successfully for user ID {user_id}"}
        else:
            logging.error("Error User ID must be provided for profile update")
            raise HTTPException(status_code=400, detail="User ID must be provided for profile update")
    else:
        # If the user is not an admin, they can only update their own profile
        if user_id != uid:
            logging.error("Forbidden: You do not have permission to update other user's profile")
            raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to update other user's profile")
        
        # Update the user's own profile
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
        update_values.append(uid)

        # Execute the update query
        QueryRun(db, update_query, update_values)
        logging.info("user profile update sucess")
        return {"message": "User profile updated successfully"}
    
# Delete user
@BasicRouter.delete("/delete-user/{user_id}", tags=['Authentication'])
async def delete_user(
    user_id:Optional[int]=None,
    db: str = Depends(get_db),
    token: str = Depends(is_token_valid_v2)
):  
    dec_tok = await decode_jwt(token=token)
    uid = dec_tok['id']
    user_role_tuple = QueryRun_Single(db, "SELECT user_role FROM User WHERE id = ?", (uid,))
    if user_role_tuple is None:
        logging.error("Fail to delete user user not found")
        raise HTTPException(status_code=404, detail="User not found")

    user_role = user_role_tuple[0]  # Extract the first element of the tuple
    # Check if the user is an admin
    if user_role == 'admin':
        # Admin can delete any user's account
        delete_query = "DELETE FROM User WHERE id = ?"
        
        QueryRun_Single(dp_paths,"""
                                DELETE FROM User_Permission
                                WHERE user_id IN (
                                    SELECT id
                                    FROM User
                                    WHERE id = ?
                                )
                        """,(uid,))
        
        QueryRun_Single(dp_paths,"""
                                DELETE FROM User_Token
                                WHERE user_id IN (
                                    SELECT id
                                    FROM User
                                    WHERE id = ?
                                )
                        """,(uid,))
        QueryRun(db, delete_query, (user_id,))
        logging.info("User delete sucess")
        return {"message": "User deleted successfully"}

    # If not an admin, check if the user is trying to delete their own account
    if user_id != uid:
        raise HTTPException(status_code=403, detail="Forbidden: You do not have permission to delete this user")

    # Delete the user's own account
    delete_query = "DELETE FROM User WHERE id = ?"
    QueryRun(db, delete_query, (uid,))
    return {"message": "Your account has been deleted successfully"}

### Set File permission for user that user can access

### Add permission
@BasicRouter.post("/add_filepath_permission", tags=['UserFileAccess'], name="File Permission", description="Set file read, write, update, delete, and download permissions")
async def set_file_permission(file_paths: List[str], permission: str|None=None, token: str = Depends(is_token_valid_v2)):
    dec_tok = await decode_jwt(token=token)
    uid = dec_tok['id']
    
    # Check if the user is an admin
    user_role_tuple = QueryRun_Single(dp_paths, "SELECT user_role FROM User WHERE id = ?", (uid,))
    if user_role_tuple[0] == "admin":
        # Check if permission for the file paths already exists
        existing_permissions = QueryRun(dp_paths, "SELECT filepath FROM User_Permission WHERE user_id = ? AND filepath IN (?)", (uid, file_paths))
        if existing_permissions:
            logging.error("400 Permission for some file paths already exists.")
            raise HTTPException(400, "Permission for some file paths already exists.")
        
        try:
            # Insert permissions into the User_Permission table
            for file_path in file_paths:
                QueryRun(dp_paths, "INSERT INTO User_Permission (user_id, permission, filepath) VALUES (?, ?, ?)", (uid, permission, file_path))
            logging.info("Permissions added successfully.")
            return {"message": "Permissions added successfully."}
        except Exception as e:
            raise HTTPException(500, f"Failed to insert permissions: {str(e)}")
      
    else:
        raise HTTPException(403, "Only admins are allowed to change permissions.")

## Get Permsission:
@BasicRouter.get("/get_user_permission", tags=['UserFileAccess'], name="Get permission for current user")
async def get_permission(token: str = Depends(is_token_valid_v2)):
    dec_tok = await decode_jwt(token=token)
    gcid = dec_tok['id']
    user_role_tuple = QueryRun_Single(dp_paths, "SELECT user_role FROM User WHERE id = ?", (gcid,))
    
    if user_role_tuple:
        user_role = user_role_tuple[0]
        if user_role in ("admin", "user"):
            query = """
                SELECT User_Permission.id, User_Permission.filepath, User_Permission.permission
                FROM User
                JOIN User_Permission ON User.id = User_Permission.user_id
                WHERE User.id = ?
            """
            res = QueryRun(dp_paths, query, (gcid,))
            
            # If there are results, return them, otherwise return an empty list
            if res is not None:
                return {"Query res": res}
            else:
                logging.error("Fetch user permission erorr: No permissions found for the user")
                return {"error": "No permissions found for the user"}  # Return an error message
        else:
            logging.error("Permission getch error invaid user role")
            return {"error": "Invalid user role"}  # Handle case where user role is not 'admin' or 'user'
    else:
        logging.error("user not found for thi permission")
        return {"error": "User not found"}  # Handle case where user ID is not found



### Edit permission\

@BasicRouter.patch("/edit_permissions", tags=['UserFileAccess'], name="User edit permission")
async def update_permission(file_paths: List[str], id: int, permission: Optional[str] = None, token: str = Depends(is_token_valid_v2)):
    dec_tok = await decode_jwt(token=token)
    gcid = dec_tok['id']
    user_role_tuple = QueryRun_Single(dp_paths, "SELECT user_role FROM User WHERE id = ?", (gcid,))
    
    if user_role_tuple and user_role_tuple[0] == "admin":
        # Check if user with provided id exists
        user_exists = QueryRun_Single(dp_paths, "SELECT id FROM User WHERE id = ?", (id,))
        if user_exists:
            # Update permissions for each file path individually
            for file_path in file_paths:
                # Check if the permission for the file path already exists
                existing_permission = QueryRun_Single(dp_paths, "SELECT permission FROM User_Permission WHERE user_id = ? AND filepath = ?", (id, file_path))
                if existing_permission:
                    # Permission already exists, update it
                    update_query = """
                    UPDATE User_Permission
                    SET permission = ?
                    WHERE user_id = ? AND filepath = ?
                    """
                    QueryRun_Single(dp_paths, update_query, (permission, id, file_path))
                else:
                    # Permission doesn't exist, insert a new row
                    insert_query = """
                    INSERT INTO User_Permission (user_id, permission, filepath)
                    VALUES (?, ?, ?)
                    """
                    QueryRun_Single(dp_paths, insert_query, (id, permission, file_path))
            logging.info("Permission for file update sucess")
            return {"message": "Permissions updated successfully"}
        else:
            logging.error("user not found for permisison to set")
            return {"message": f"User with id {id} not found."}, 404
    else:
        logging.error("Admin can edit permission for folders.")
        return {"message": "Only admin users can update permissions."}, 403
##BST for file 
 

 

### Access local using BST
@BasicRouter.get("/local-file", tags=["Local-File"],name="Binary tree File system ",description="Won't accept Entire disk may stuck. \n\n Donot enter disk letter insted pass file path like d:/folder")
async def create_file_tree_endpoint(path: str,token: str = Depends(is_token_valid_v2)):
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

@BasicRouter.get("/local-simpSearch", tags=["Local-File"], description="Search file using Simple method")
async def search_simple(path: str = Query(...),token: str = Depends(is_token_valid_v2)):
    if os.path.exists(path):
        return await get_directory_structure(path)
    else:
        raise HTTPException(404, f"File path doesn't exist: '{path}'")
     
### Download file
@BasicRouter.get("/download-file/", tags=["Local-File"], name="Download File")
async def download_file(file_path: str, token: str = Depends(is_token_valid_v2)):
    dec_tok = await decode_jwt(token=token)
    uid = dec_tok['id']
    user_role_tuple = QueryRun_Single(dp_paths, "SELECT user_role FROM User WHERE id = ?", (uid,))

    if user_role_tuple:
        user_role = user_role_tuple[0]  # Extract the role from the tuple
        if user_role == "admin" or user_role == "user":
            """
            Download a file from the binary tree file system.

            :param file_path: The path to the file relative to the root of the file system.
            """
            # Check if the file path exists in the file system
            if not os.path.exists(file_path):
                raise HTTPException(status_code=404, detail="File not found")

            # Return the file as a response
            return FileResponse(file_path)
        else:
            raise HTTPException(status_code=403, detail="Access denied: You do not have permission to download files")
    else:
        raise HTTPException(status_code=500, detail="Failed to fetch user role from the database")

## List local dirs

@BasicRouter.get("/list_dirs", tags=["Local-File"],name="Directory List") 
async def get_dirs(token: str = Depends(is_token_valid_v2) ):
    # Get a list of all disk partitions
    disk_partitions = psutil.disk_partitions()

    # Extract the disk names from the disk partitions
    disks = [partition.device for partition in disk_partitions]

    return {"Available disks": disks}

### Delete files 
@BasicRouter.delete("/delete/{file_path:path}",tags=["Delete"],name="Delete files danger zone",description="Danger zone delete files -be careful -Once file deleted wont br recover")
async def delete_file_or_folder(file_path: str,token: str = Depends(is_token_valid_v2)):
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


async def recover_files(drive: str, selected_formats: List[str], destination_folder: str,token: str = Depends(is_token_valid_v2)):
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

@BasicRouter.post("/recover-files/", tags=["Data Recovery"])
async def recover_files_endpoint(
    drive: str = Form(...),
    selected_formats: List[str] = Form(...),
    destination_folder: str = Form(...) ,
    token: str = Depends(is_token_valid_v2)
):
    if not os.path.exists(destination_folder):
        os.mkdir(destination_folder)
        raise HTTPException(status_code=400, detail="Destination folder does not exist")
       
    recovered_files = await recover_files(drive, selected_formats, destination_folder)
    return {"recovered_files": recovered_files}

@BasicRouter.get("/download-recovered-file/", tags=["Data Recovery"])
async def download_recovered_file(file_path: str,token: str = Depends(is_token_valid_v2)):
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(file_path)