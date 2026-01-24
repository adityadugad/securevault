import os
import sqlite3

DB_PATH = os.getenv("DATABASE_PATH", "securevault.db")

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
