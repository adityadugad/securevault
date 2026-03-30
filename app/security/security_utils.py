from datetime import datetime, timedelta
from app.database import conn


# =========================================================
# RISK SCORE CONFIG
# =========================================================

RISK_SCORES = {
    "failed_login": 10,
    "wrong_otp": 15,
    "too_many_requests": 20,
    "admin_failure": 40,
    "decrypt_abuse": 25,
    "multiple_ips": 20,
}


# =========================================================
# LOG SECURITY EVENT
# =========================================================

def log_security_event(
    email: str = None,
    ip_address: str = None,
    endpoint: str = None,
    event_type: str = None,
    status: str = "warning"
):
    cur = conn.cursor()

    risk_score = RISK_SCORES.get(event_type, 0)

    cur.execute("""
    INSERT INTO security_logs
    (email, ip_address, endpoint, event_type, risk_score, status)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        email,
        ip_address,
        endpoint,
        event_type,
        risk_score,
        status
    ))

    conn.commit()
    cur.close()


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(total_score: int) -> str:
    if total_score >= 80:
        return "critical"
    elif total_score >= 50:
        return "high"
    elif total_score >= 25:
        return "medium"
    return "low"


# =========================================================
# GET USER RISK SCORE
# =========================================================

def get_user_risk_score(email: str) -> int:
    cur = conn.cursor()

    cur.execute("""
    SELECT COALESCE(SUM(risk_score), 0)
    FROM security_logs
    WHERE email = ?
    AND created_at >= datetime('now', '-24 hours')
    """, (email,))

    score = cur.fetchone()[0] or 0
    cur.close()

    return score


# =========================================================
# MULTIPLE IP DETECTION
# =========================================================

def check_multiple_ips(email: str, hours: int = 1) -> bool:
    cur = conn.cursor()

    cur.execute("""
    SELECT COUNT(DISTINCT ip_address)
    FROM login_history
    WHERE email = ?
    AND created_at >= datetime('now', ?)
    """, (
        email,
        f'-{hours} hours'
    ))

    ip_count = cur.fetchone()[0]
    cur.close()

    return ip_count >= 3


# =========================================================
# ACCOUNT LOCK HELPERS
# =========================================================

def is_account_locked(email: str, lock_type: str) -> bool:
    cur = conn.cursor()

    cur.execute("""
    SELECT locked_until
    FROM account_locks
    WHERE email = ?
    AND lock_type = ?
    ORDER BY id DESC
    LIMIT 1
    """, (email, lock_type))

    row = cur.fetchone()
    cur.close()

    if not row:
        return False

    locked_until = datetime.fromisoformat(row[0])

    return datetime.utcnow() < locked_until


def lock_account(email: str, lock_type: str, minutes: int):
    locked_until = (datetime.utcnow() + timedelta(minutes=minutes)).isoformat()

    cur = conn.cursor()

    cur.execute("""
    INSERT INTO account_locks
    (email, lock_type, locked_until)
    VALUES (?, ?, ?)
    """, (
        email,
        lock_type,
        locked_until
    ))

    conn.commit()
    cur.close()


# =========================================================
# FAILED ATTEMPT HELPERS
# =========================================================

def get_failed_attempts(email: str, event_type: str, minutes: int = 30) -> int:
    cur = conn.cursor()

    cur.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE email = ?
    AND event_type = ?
    AND created_at >= datetime('now', ?)
    """, (
        email,
        event_type,
        f'-{minutes} minutes'
    ))

    count = cur.fetchone()[0]
    cur.close()

    return count


def reset_failed_attempts(email: str, event_type: str):
    cur = conn.cursor()

    cur.execute("""
    DELETE FROM security_logs
    WHERE email = ?
    AND event_type = ?
    """, (
        email,
        event_type
    ))

    conn.commit()
    cur.close()
