import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

database_uri = os.getenv('DATABASE_URI', 'D:/Proyectos/HashMail/hashmail.db')

def get_db_connection():
    """Establece la conexión con la base de datos"""
    print(f"Connecting to database: {database_uri}")
    conn = sqlite3.connect('hashmail.db')
    #conn = sqlite3.connect('D:/Proyectos/HashMail/hashmail.db')
    return conn

def create_table():
    """Crea la tabla de hashes comprometidos si no existe"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS compromised_hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            email_hash TEXT UNIQUE NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def insert_multiple_hashes(hashes, emails):
    """Inserta múltiples hashes comprometidos junto con los correos electrónicos en la base de datos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.executemany("INSERT OR IGNORE INTO compromised_hashes (email, email_hash) VALUES (?, ?)", [(email, hash) for email, hash in zip(emails, hashes)])
    conn.commit()
    conn.close()

def is_compromised(email_hash):
    """Verifica si el hash de un correo electrónico está comprometido"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM compromised_hashes WHERE email_hash = ?", (email_hash,))
    result = cursor.fetchone()
    conn.close()
    return result is not None
