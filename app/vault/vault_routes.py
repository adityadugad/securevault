from fastapi import APIRouter, Depends, Body
from app.auth.auth_utils import get_current_user
from app.vault.vault_utils import encrypt_text, decrypt_text
from app.database import conn

# ✅ IMPORT REAL SVM PREDICTOR
from app.ml.password_strength_model import predict_strength

# Router (NO prefix to avoid /vault/vault bug)
vault_router = APIRouter(tags=["Vault"])

# =========================================================
# NOTES
# =========================================================

@vault_router.post("/notes")
def add_note(title: str, content: str, user=Depends(get_current_user)):
    enc = encrypt_text(content)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO notes (user_email, title, ciphertext, nonce) VALUES (?, ?, ?, ?)",
        (user, title, enc["ciphertext"], enc["nonce"])
    )
    conn.commit()
    cur.close()
    return {"message": "Encrypted note stored successfully"}


@vault_router.get("/notes")
def list_notes(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, ciphertext, created_at FROM notes WHERE user_email = ?",
        (user,)
    )
    rows = cur.fetchall()
    cur.close()
    return {"notes": rows}


@vault_router.get("/notes/decrypted")
def list_notes_decrypted(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, title, ciphertext, nonce, created_at FROM notes WHERE user_email = ?",
        (user,)
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "notes": [
            {
                "id": r[0],
                "title": r[1],
                "content": decrypt_text(r[2], r[3]),
                "created_at": r[4],
            }
            for r in rows
        ]
    }


@vault_router.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute("DELETE FROM notes WHERE id = ? AND user_email = ?", (note_id, user))
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
        "INSERT INTO todos (user_email, ciphertext, nonce) VALUES (?, ?, ?)",
        (user, enc["ciphertext"], enc["nonce"])
    )
    conn.commit()
    cur.close()
    return {"message": "Encrypted todo stored successfully"}


@vault_router.get("/todos")
def list_todos(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ciphertext, created_at FROM todos WHERE user_email = ?",
        (user,)
    )
    rows = cur.fetchall()
    cur.close()
    return {"todos": rows}


@vault_router.get("/todos/decrypted")
def list_todos_decrypted(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, ciphertext, nonce, created_at FROM todos WHERE user_email = ?",
        (user,)
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "todos": [
            {
                "id": r[0],
                "task": decrypt_text(r[1], r[2]),
                "created_at": r[3],
            }
            for r in rows
        ]
    }


@vault_router.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute("DELETE FROM todos WHERE id = ? AND user_email = ?", (todo_id, user))
    conn.commit()
    cur.close()
    return {"message": "Todo deleted successfully"}

# =========================================================
# PASSWORD VAULT
# =========================================================

@vault_router.post("/passwords")
def add_password(site: str, username: str, password: str, user=Depends(get_current_user)):
    enc = encrypt_text(password)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO passwords (user_email, site, username, ciphertext, nonce)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user, site, username, enc["ciphertext"], enc["nonce"])
    )
    conn.commit()
    cur.close()
    return {"message": "Encrypted password stored successfully"}


@vault_router.get("/passwords")
def list_passwords(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, site, username, created_at FROM passwords WHERE user_email = ?",
        (user,)
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
def list_passwords_decrypted(user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute(
        "SELECT id, site, username, ciphertext, nonce, created_at FROM passwords WHERE user_email = ?",
        (user,)
    )
    rows = cur.fetchall()
    cur.close()

    return {
        "passwords": [
            {
                "id": r[0],
                "site": r[1],
                "username": r[2],
                "password": decrypt_text(r[3], r[4]),
                "created_at": r[5],
            }
            for r in rows
        ]
    }


@vault_router.delete("/passwords/{password_id}")
def delete_password(password_id: int, user=Depends(get_current_user)):
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id = ? AND user_email = ?", (password_id, user))
    conn.commit()
    cur.close()
    return {"message": "Password deleted successfully"}

# =========================================================
# PASSWORD STRENGTH CHECK (REAL SVM – WARNING ONLY)
# =========================================================

@vault_router.post("/password-strength")
def password_strength_check(
    data: dict = Body(...),
    user=Depends(get_current_user)
):
    pwd = data.get("password", "")
    strength = predict_strength(pwd)
    return {"strength": strength}
