from app.database import conn
from user_agents import parse
from datetime import datetime


# =========================================================
# RECORD LOGIN HISTORY
# =========================================================

def record_login_history(
    email: str,
    ip_address: str,
    user_agent: str,
    success: bool
):
    parsed_agent = parse(user_agent or "")

    browser = parsed_agent.browser.family
    device_type = "Mobile" if parsed_agent.is_mobile else "Desktop"

    cur = conn.cursor()

    cur.execute("""
    INSERT INTO login_history
    (email, ip_address, user_agent, browser, device_type, success)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        email,
        ip_address,
        user_agent,
        browser,
        device_type,
        1 if success else 0
    ))

    conn.commit()
    cur.close()


# =========================================================
# CREATE SESSION
# =========================================================

def create_session(
    email: str,
    jwt_token: str,
    ip_address: str,
    user_agent: str
):
    parsed_agent = parse(user_agent or "")

    browser = parsed_agent.browser.family
    device_type = "Mobile" if parsed_agent.is_mobile else "Desktop"

    cur = conn.cursor()

    cur.execute("""
    INSERT INTO user_sessions
    (email, jwt_token, ip_address, user_agent, browser, device_type)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        email,
        jwt_token,
        ip_address,
        user_agent,
        browser,
        device_type
    ))

    conn.commit()
    cur.close()


# =========================================================
# GET ACTIVE SESSIONS
# =========================================================

def get_active_sessions(email: str):
    cur = conn.cursor()

    cur.execute("""
    SELECT id, ip_address, browser, device_type,
           created_at, last_activity
    FROM user_sessions
    WHERE email = ?
    AND is_active = 1
    ORDER BY created_at DESC
    """, (email,))

    sessions = cur.fetchall()
    cur.close()

    return sessions


# =========================================================
# REVOKE OTHER SESSIONS
# =========================================================

def revoke_other_sessions(email: str, current_token: str):
    cur = conn.cursor()

    cur.execute("""
    UPDATE user_sessions
    SET is_active = 0
    WHERE email = ?
    AND jwt_token != ?
    """, (
        email,
        current_token
    ))

    conn.commit()
    cur.close()


# =========================================================
# UPDATE SESSION ACTIVITY
# =========================================================

def update_session_activity(jwt_token: str):
    cur = conn.cursor()

    cur.execute("""
    UPDATE user_sessions
    SET last_activity = ?
    WHERE jwt_token = ?
    """, (
        datetime.utcnow().isoformat(),
        jwt_token
    ))

    conn.commit()
    cur.close()