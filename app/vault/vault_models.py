from app.database import conn


def _add_column_if_not_exists(cur, table, column_def):
    """
    Safe migration helper.
    Adds column only if it does not already exist.
    """
    table_info = cur.execute(f"PRAGMA table_info({table})").fetchall()
    existing_columns = [col[1] for col in table_info]

    column_name = column_def.split()[0]

    if column_name not in existing_columns:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


def create_vault_tables():
    cur = conn.cursor()

    # -------------------------------------------------
    # NOTES
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        title TEXT,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Add new columns safely
    _add_column_if_not_exists(cur, "notes", "kem_ciphertext TEXT")
    _add_column_if_not_exists(cur, "notes", "encryption_type TEXT DEFAULT 'BACKUP'")

    # -------------------------------------------------
    # TODOS
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        completed INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    _add_column_if_not_exists(cur, "todos", "kem_ciphertext TEXT")
    _add_column_if_not_exists(cur, "todos", "encryption_type TEXT DEFAULT 'BACKUP'")

    # -------------------------------------------------
    # PASSWORDS
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        nonce TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    _add_column_if_not_exists(cur, "passwords", "kem_ciphertext TEXT")
    _add_column_if_not_exists(cur, "passwords", "encryption_type TEXT DEFAULT 'BACKUP'")

    conn.commit()
    cur.close()
