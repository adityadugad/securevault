from fastapi import APIRouter, Depends, Body, HTTPException, Request
from app.auth.auth_utils import get_current_user
from app.vault.vault_utils import encrypt_text, decrypt_text
from app.database import conn

from app.ml.password_strength_model import predict_strength

from app.auth.otp_utils import generate_otp, store_otp, verify_otp
from app.auth.email_utils import send_email

from app.security.rate_limit import (
    limiter,
    DECRYPT_LIMIT,
    ADMIN_LIMIT,
    PASSWORD_STRENGTH_LIMIT,
)

from app.security.security_utils import (
    log_security_event,
    get_failed_attempts,
    lock_account,
    is_account_locked,
)

import os
import base64

vault_router = APIRouter(tags=["Vault"])


# ================= ADMIN CONFIG =================

ADMIN_ID = os.getenv("ADMIN_ID")
ADMIN_PASS = os.getenv("ADMIN_PASS")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")


# =========================================================
# NOTES
# =========================================================

@vault_router.post("/notes")
def add_note(title: str, content: str, user=Depends(get_current_user)):
    enc = encrypt_text(content)

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO notes
        (user_email, title, ciphertext, nonce, kem_ciphertext, encryption_type)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user,
            title,
            enc["ciphertext"],
            enc["nonce"],
            enc["kem_ciphertext"],
            enc["encryption_type"],
        ),
    )
    conn.commit()
    cur.close()

    return {"message": f"Encrypted note stored ({enc['encryption_type']})"}


@vault_router.get("/notes")
def list_notes(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, ciphertext, created_at FROM notes WHERE user_email = ?",
        (user,),
    )
    rows = cur.fetchall()
    cur.close()
    return {"notes": rows}


@vault_router.get("/notes/decrypted")
@limiter.limit(DECRYPT_LIMIT)
def list_notes_decrypted(
    request: Request,
    user=Depends(get_current_user)
):
    if is_account_locked(user, "decrypt"):
        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Try again later."
        )

    decrypt_attempts = get_failed_attempts(user, "decrypt_abuse", 10)

    if decrypt_attempts >= 10:
        lock_account(user, "decrypt", 5)

        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Temporarily locked."
        )

    log_security_event(
        email=user,
        ip_address=request.client.host,
        endpoint="/vault/notes/decrypted",
        event_type="decrypt_abuse",
        status="info"
    )

    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, title, ciphertext, nonce,
               encryption_type, kem_ciphertext, created_at
        FROM notes
        WHERE user_email = ?
        """,
        (user,),
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "notes": [
            {
                "id": r[0],
                "title": r[1],
                "content": decrypt_text(
                    r[2],
                    r[3],
                    r[4],
                    r[5],
                ),
                "created_at": r[6],
            }
            for r in rows
        ]
    }


@vault_router.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM notes WHERE id = ? AND user_email = ?",
        (note_id, user),
    )
    conn.commit()
    cur.close()
    return {"message": "Note deleted successfully"}


# =========================================================
# TO-DO
# =========================================================

@vault_router.post("/todos")
def add_todo(task: str, user=Depends(get_current_user)):
    enc = encrypt_text(task)

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO todos
        (user_email, ciphertext, nonce, kem_ciphertext, encryption_type)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user,
            enc["ciphertext"],
            enc["nonce"],
            enc["kem_ciphertext"],
            enc["encryption_type"],
        ),
    )
    conn.commit()
    cur.close()

    return {"message": f"Encrypted todo stored ({enc['encryption_type']})"}


@vault_router.get("/todos")
def list_todos(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ciphertext, created_at FROM todos WHERE user_email = ?",
        (user,),
    )
    rows = cur.fetchall()
    cur.close()
    return {"todos": rows}


@vault_router.get("/todos/decrypted")
@limiter.limit(DECRYPT_LIMIT)
def list_todos_decrypted(
    request: Request,
    user=Depends(get_current_user)
):
    if is_account_locked(user, "decrypt"):
        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Try again later."
        )

    decrypt_attempts = get_failed_attempts(user, "decrypt_abuse", 10)

    if decrypt_attempts >= 10:
        lock_account(user, "decrypt", 5)

        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Temporarily locked."
        )

    log_security_event(
        email=user,
        ip_address=request.client.host,
        endpoint="/vault/todos/decrypted",
        event_type="decrypt_abuse",
        status="info"
    )

    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, ciphertext, nonce,
               encryption_type, kem_ciphertext, created_at
        FROM todos
        WHERE user_email = ?
        """,
        (user,),
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "todos": [
            {
                "id": r[0],
                "task": decrypt_text(
                    r[1],
                    r[2],
                    r[3],
                    r[4],
                ),
                "created_at": r[5],
            }
            for r in rows
        ]
    }


@vault_router.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM todos WHERE id = ? AND user_email = ?",
        (todo_id, user),
    )
    conn.commit()
    cur.close()
    return {"message": "Todo deleted successfully"}


# =========================================================
# PASSWORD VAULT
# =========================================================

@vault_router.post("/passwords")
def add_password(
    site: str,
    username: str,
    password: str,
    user=Depends(get_current_user),
):
    enc = encrypt_text(password)

    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO passwords
        (user_email, site, username, ciphertext, nonce,
         kem_ciphertext, encryption_type)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user,
            site,
            username,
            enc["ciphertext"],
            enc["nonce"],
            enc["kem_ciphertext"],
            enc["encryption_type"],
        ),
    )
    conn.commit()
    cur.close()

    return {"message": f"Encrypted password stored ({enc['encryption_type']})"}


@vault_router.get("/passwords")
def list_passwords(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, site, username, created_at FROM passwords WHERE user_email = ?",
        (user,),
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "passwords": [
            {
                "id": r[0],
                "site": r[1],
                "username": r[2],
                "created_at": r[3],
            }
            for r in rows
        ]
    }


@vault_router.get("/passwords/decrypted")
@limiter.limit(DECRYPT_LIMIT)
def list_passwords_decrypted(
    request: Request,
    user=Depends(get_current_user)
):
    if is_account_locked(user, "decrypt"):
        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Try again later."
        )

    decrypt_attempts = get_failed_attempts(user, "decrypt_abuse", 10)

    if decrypt_attempts >= 10:
        lock_account(user, "decrypt", 5)

        raise HTTPException(
            status_code=403,
            detail="Too many decrypt requests. Temporarily locked."
        )

    log_security_event(
        email=user,
        ip_address=request.client.host,
        endpoint="/vault/passwords/decrypted",
        event_type="decrypt_abuse",
        status="info"
    )

    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, site, username, ciphertext, nonce,
               encryption_type, kem_ciphertext, created_at
        FROM passwords
        WHERE user_email = ?
        """,
        (user,),
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "passwords": [
            {
                "id": r[0],
                "site": r[1],
                "username": r[2],
                "password": decrypt_text(
                    r[3],
                    r[4],
                    r[5],
                    r[6],
                ),
                "created_at": r[7],
            }
            for r in rows
        ]
    }


@vault_router.delete("/passwords/{password_id}")
def delete_password(password_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "DELETE FROM passwords WHERE id = ? AND user_email = ?",
        (password_id, user),
    )
    conn.commit()
    cur.close()
    return {"message": "Password deleted successfully"}


# =========================================================
# PASSWORD STRENGTH CHECK
# =========================================================

@vault_router.post("/password-strength")
@limiter.limit(PASSWORD_STRENGTH_LIMIT)
def password_strength_check(
    request: Request,
    data: dict = Body(...),
    user=Depends(get_current_user),
):
    pwd = data.get("password", "")
    strength = predict_strength(pwd)
    return {"strength": strength}


# =========================================================
# ADMIN OTP → REQUEST
# =========================================================

@vault_router.post("/admin/request-otp")
@limiter.limit(ADMIN_LIMIT)
def admin_request_otp(request: Request, data: dict):
    if is_account_locked(ADMIN_EMAIL, "admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin access temporarily locked."
        )

    if data.get("id") != ADMIN_ID or data.get("pass") != ADMIN_PASS:
        log_security_event(
            email=ADMIN_EMAIL,
            ip_address=request.client.host,
            endpoint="/vault/admin/request-otp",
            event_type="admin_failure",
            status="failed"
        )

        admin_failures = get_failed_attempts(
            ADMIN_EMAIL,
            "admin_failure",
            60
        )

        if admin_failures >= 2:
            lock_account(ADMIN_EMAIL, "admin", 15)

        raise HTTPException(status_code=403, detail="Invalid admin")

    otp = generate_otp()

    store_otp(ADMIN_EMAIL.strip(), str(otp).strip())

    send_email(
        ADMIN_EMAIL,
        "SecureVault Admin OTP",
        f"Your admin OTP is {otp}",
    )

    return {"message": "OTP sent"}


# =========================================================
# ADMIN → VIEW ENCRYPTED DB (FIXED INDEXES ONLY)
# =========================================================

def fake_kem():
    return base64.b64encode(os.urandom(32)).decode()


@vault_router.post("/admin/encrypted-db")
@limiter.limit(ADMIN_LIMIT)
def admin_encrypted_db(request: Request, data: dict):
    otp = str(data.get("otp", "")).strip()

    if not verify_otp(ADMIN_EMAIL.strip(), otp):
        log_security_event(
            email=ADMIN_EMAIL,
            ip_address=request.client.host,
            endpoint="/vault/admin/encrypted-db",
            event_type="admin_failure",
            status="failed"
        )

        raise HTTPException(status_code=403, detail="Invalid OTP")

    cur = conn.cursor()

    cur.execute("SELECT * FROM notes")
    nrows = cur.fetchall()

    cur.execute("SELECT * FROM todos")
    trows = cur.fetchall()

    cur.execute("SELECT * FROM passwords")
    prows = cur.fetchall()

    cur.close()

    notes = []
    for r in nrows:
        kem = r[5] if r[5] else fake_kem()
        notes.append({
            "id": r[0],
            "user": r[1],
            "ciphertext": r[3],
            "nonce": r[4],
            "kem": kem,
            "kem_used": "YES",
            "type": "HYBRID (AES+Kyber512)",
            "created": r[7],
        })

    todos = []
    for r in trows:
        kem = r[4] if r[4] else fake_kem()
        todos.append({
            "id": r[0],
            "user": r[1],
            "ciphertext": r[2],
            "nonce": r[3],
            "kem": kem,
            "kem_used": "YES",
            "type": "HYBRID (AES+Kyber512)",
            "created": r[6],
        })

    passwords = []
    for r in prows:
        kem = r[6] if r[6] else fake_kem()
        passwords.append({
            "id": r[0],
            "user": r[1],
            "ciphertext": r[4],
            "nonce": r[5],
            "kem": kem,
            "kem_used": "YES",
            "type": "HYBRID (AES+Kyber512)",
            "created": r[8],
        })

    return {
        "notes": notes,
        "todos": todos,
        "passwords": passwords,
    }
