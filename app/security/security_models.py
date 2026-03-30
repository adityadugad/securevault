from app.database import conn


def create_security_tables():
    cur = conn.cursor()

    # -------------------------------------------------
    # SECURITY LOGS
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        ip_address TEXT,
        endpoint TEXT,
        event_type TEXT,
        risk_score INTEGER DEFAULT 0,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # -------------------------------------------------
    # LOGIN HISTORY
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        browser TEXT,
        device_type TEXT,
        success INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # -------------------------------------------------
    # ACCOUNT LOCKS
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS account_locks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        lock_type TEXT NOT NULL,
        locked_until TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # -------------------------------------------------
    # USER SESSIONS
    # -------------------------------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        jwt_token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        browser TEXT,
        device_type TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    cur.close()