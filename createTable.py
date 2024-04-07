import sqlite3
from typing import Union
def create_tables(db_file):
    """Creates the 'User' and 'User_Permission' tables in the specified SQLite database file.

    Args:
        db_file (str): The path to the SQLite database file.
    """

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    user_table = """
    CREATE TABLE IF NOT EXISTS User (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        creation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_online BOOLEAN NOT NULL,
        token_id INT,
        user_role VARCHAR,
        FOREIGN KEY (token_id) REFERENCES User_Token(user_id)
    )
    """

    user_permission_table = """
    CREATE TABLE IF NOT EXISTS User_Permission (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INT,
        permission VARCHAR(100) NOT NULL,
        filepath VARCHAR(255) NOT NULL UNIQUE,
        FOREIGN KEY (user_id) REFERENCES User(id)
    )
    """

    user_token_table = """
    CREATE TABLE IF NOT EXISTS User_Token (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INT,
        token VARCHAR(255) UNIQUE,
        FOREIGN KEY (user_id) REFERENCES User(id)
    )
    """


    try:
        cursor.execute(user_table)
        cursor.execute(user_permission_table)
        cursor.execute(user_token_table)
        conn.commit()
        print("Tables created successfully!")
    except sqlite3.Error as error:
        print(f"Error creating tables: {error}")
    finally:
        conn.close()
        
        ### Run SQL Query
def QueryRun(db: str, q: str, params: tuple = ()) -> list:
    conn = sqlite3.connect(db)
    cursor = conn.cursor()

    try:
        cursor.execute(q, params)
        results = cursor.fetchall()
        conn.commit()
        return results
    except sqlite3.Error as error:
        print(f"Error executing query: {error}")
        return []
    finally:
        conn.close()

def QueryRun_Single(db: str, q: str, params: tuple = ()) -> Union[tuple, None]:
    conn = sqlite3.connect(db)
    cursor = conn.cursor()

    try:
        cursor.execute(q, params)
        result = cursor.fetchone()  # Fetch a single row
        conn.commit()
        return result  # Return the single row or None if no row is found
    except sqlite3.Error as error:
        print(f"Error executing query: {error}")
        return None
    finally:
        conn.close()