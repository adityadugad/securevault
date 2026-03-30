COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "password",
    "password123",
    "admin",
    "admin123",
    "qwerty",
    "abc123",
    "welcome",
    "letmein",
    "iloveyou",
    "football",
    "monkey",
    "dragon",
    "sunshine",
    "princess",
    "securevault",
    "india123",
    "aditya123"
}


def is_common_password(password: str) -> bool:
    return password.lower().strip() in COMMON_PASSWORDS


def get_password_warning(password: str):
    pwd = password.strip()

    if len(pwd) < 8:
        return "Password must be at least 8 characters long"

    if not any(c.isupper() for c in pwd):
        return "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in pwd):
        return "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in pwd):
        return "Password must contain at least one number"

    if not any(not c.isalnum() for c in pwd):
        return "Password must contain at least one special character"

    if is_common_password(pwd):
        return "This password is too common and unsafe"

    return None