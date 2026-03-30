from fastapi import APIRouter, Depends, HTTPException, Request
from app.auth.jwt_dependency import get_current_user
from app.database import conn
from app.security.session_utils import (
    get_active_sessions,
    revoke_other_sessions,
    update_session_activity,
)
from app.security.security_utils import (
    get_user_risk_score,
    get_risk_level,
)

security_router = APIRouter(tags=["Security"])


# =========================================================
# ACTIVE SESSIONS
# =========================================================

@security_router.get("/sessions")
def active_sessions(user=Depends(get_current_user)):
    sessions = get_active_sessions(user)

    return {
        "sessions": [
            {
                "id": s[0],
                "ip_address": s[1],
                "browser": s[2],
                "device_type": s[3],
                "created_at": s[4],
                "last_activity": s[5],
            }
            for s in sessions
        ]
    }


# =========================================================
# LOGOUT OTHER DEVICES
# =========================================================

@security_router.post("/logout-other-devices")
def logout_other_devices(
    request: Request,
    user=Depends(get_current_user)
):
    auth_header = request.headers.get("authorization")

    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header.replace("Bearer ", "").strip()

    revoke_other_sessions(user, token)

    return {
        "message": "Logged out from all other devices successfully"
    }


# =========================================================
# SECURITY DASHBOARD
# =========================================================

@security_router.get("/dashboard")
def security_dashboard(user=Depends(get_current_user)):
    cur = conn.cursor()

    cur.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE email = ?
    """, (user,))
    total_events = cur.fetchone()[0]

    cur.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE email = ?
    AND event_type = 'failed_login'
    """, (user,))
    failed_logins = cur.fetchone()[0]

    cur.execute("""
    SELECT COUNT(*)
    FROM security_logs
    WHERE email = ?
    AND event_type = 'wrong_otp'
    """, (user,))
    wrong_otps = cur.fetchone()[0]

    cur.execute("""
    SELECT created_at
    FROM login_history
    WHERE email = ?
    AND success = 1
    ORDER BY id DESC
    LIMIT 1
    """, (user,))
    last_login = cur.fetchone()

    cur.close()

    risk_score = get_user_risk_score(user)

    return {
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "total_security_events": total_events,
        "failed_logins": failed_logins,
        "wrong_otps": wrong_otps,
        "last_login": last_login[0] if last_login else None,
    }
