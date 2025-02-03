import mysql.connector
from mysql.connector import Error

def get_db_connection():
    return mysql.connector.connect(
        host='mysql2.sqlpub.com',
        user='heidong',
        password='FuddpritszT3E2O6',
        database='heidong',
        port=3307
    )

def get_db_connection_old():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="123456",
            database="chat_db"
        )
        return connection
    except Error as e:
        print(f"Error connecting to MySQL Database: {e}")
        return None 