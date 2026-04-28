```javascript
// ======================================================
// SecureVault Authentication Logic (FINAL FIXED VERSION)
// Full Replaceable Code
// ======================================================


// ======================================================
// UTIL
// ======================================================

function qs(id) {
  return document.getElementById(id);
}

function setMsg(id, text, type = "") {
  const el = document.getElementById(id);
  if (!el) return;

  el.innerText = text;
  el.className = "msg " + type;
}


// ======================================================
// SAFE JSON PARSER
// Prevents "Network error" issue when backend returns
// non-JSON / server error / FastAPI exception page
// ======================================================

async function safeJson(res, fallbackMessage = "Server error") {
  try {
    return await res.json();
  } catch (e) {
    return {
      detail: fallbackMessage
    };
  }
}


// ======================================================
// SIGNUP
// ======================================================

async function signup() {
  try {
    const email = qs("email")?.value?.trim();
    const password = qs("password")?.value;

    if (!email || !password) {
      setMsg("msg", "Email and password required", "err");
      return;
    }

    setMsg("msg", "Sending OTP...");

    const res = await fetch("/auth/signup", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        password
      })
    });

    const data = await safeJson(
      res,
      "Signup failed. Please try again."
    );

    if (!res.ok) {
      const detail = data.detail || "Signup failed";

      if (detail.includes("locked")) {
        setMsg("msg", "🔒 " + detail, "err");
      }
      else if (detail.includes("Too many")) {
        setMsg("msg", "⚠️ " + detail, "err");
      }
      else {
        setMsg("msg", detail, "err");
      }

      return;
    }

    localStorage.setItem("otp_mode", "signup");
    localStorage.setItem("signup_email", email);

    window.location.href = "/static/otp.html";

  } catch (e) {
    setMsg(
      "msg",
      "Unable to connect to server",
      "err"
    );
  }
}


// ======================================================
// LOGIN (PASSWORD)
// ======================================================

async function login() {
  try {
    const email = qs("email")?.value?.trim();
    const password = qs("password")?.value;

    if (!email || !password) {
      setMsg("msg", "Email and password required", "err");
      return;
    }

    setMsg("msg", "Checking credentials...");

    const res = await fetch("/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email,
        password
      })
    });

    // IMPORTANT FIX:
    // prevents false "Network error"
    const data = await safeJson(
      res,
      "Login failed. Please try again."
    );

    if (!res.ok) {
      const detail = data.detail || "Login failed";

      // -----------------------------
      // ACCOUNT LOCKED
      // -----------------------------
      if (
        detail.includes("locked") ||
        detail.includes("Account locked")
      ) {
        setMsg(
          "msg",
          "🔒 Account locked for 10 minutes",
          "err"
        );
      }

      // -----------------------------
      // RATE LIMIT / TOO MANY REQUESTS
      // -----------------------------
      else if (
        detail.includes("Too many")
      ) {
        setMsg(
          "msg",
          "⚠️ Too many attempts. Please wait and try again.",
          "err"
        );
      }

      // -----------------------------
      // WRONG PASSWORD
      // -----------------------------
      else if (
        detail.includes("Incorrect password")
      ) {
        setMsg(
          "msg",
          "❌ Incorrect password",
          "err"
        );
      }

      // -----------------------------
      // USER NOT FOUND
      // -----------------------------
      else if (
        detail.includes("User does not exist")
      ) {
        setMsg(
          "msg",
          "❌ User does not exist",
          "err"
        );
      }

      // -----------------------------
      // EMAIL NOT VERIFIED
      // -----------------------------
      else if (
        detail.includes("Email not verified")
      ) {
        setMsg(
          "msg",
          "⚠️ Email not verified. Please verify your account first.",
          "err"
        );
      }

      // -----------------------------
      // DEFAULT
      // -----------------------------
      else {
        setMsg(
          "msg",
          detail,
          "err"
        );
      }

      return;
    }

    localStorage.setItem("otp_mode", "login");
    localStorage.setItem("login_email", email);

    window.location.href = "/static/otp.html";

  } catch (e) {
    setMsg(
      "msg",
      "Unable to connect to server",
      "err"
    );
  }
}


// ======================================================
// VERIFY OTP (UNIFIED)
// ======================================================

async function verifyOtp() {
  try {
    const otp = qs("otp")?.value?.trim();
    const mode = localStorage.getItem("otp_mode");

    if (!otp || !mode) {
      setMsg(
        "msg",
        "OTP session expired",
        "err"
      );
      return;
    }

    setMsg("msg", "Verifying OTP...");


    // ==================================================
    // SIGNUP OTP
    // ==================================================

    if (mode === "signup") {
      const email = localStorage.getItem("signup_email");

      const res = await fetch(
        `/auth/verify-signup-otp?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}`,
        {
          method: "POST"
        }
      );

      const data = await safeJson(
        res,
        "Invalid OTP"
      );

      if (!res.ok) {
        const detail = data.detail || "Invalid OTP";

        if (detail.includes("locked")) {
          setMsg("msg", "🔒 " + detail, "err");
        }
        else if (detail.includes("Too many")) {
          setMsg("msg", "⚠️ " + detail, "err");
        }
        else {
          setMsg("msg", detail, "err");
        }

        return;
      }

      setMsg(
        "msg",
        "Account verified ✅ Redirecting to login...",
        "ok"
      );

      localStorage.removeItem("otp_mode");
      localStorage.removeItem("signup_email");

      setTimeout(() => {
        window.location.href = "/";
      }, 1200);

      return;
    }


    // ==================================================
    // LOGIN OTP
    // ==================================================

    if (mode === "login") {
      const email = localStorage.getItem("login_email");

      const res = await fetch(
        `/auth/login-otp?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}`,
        {
          method: "POST"
        }
      );

      const data = await safeJson(
        res,
        "Invalid OTP"
      );

      if (!res.ok) {
        const detail = data.detail || "Invalid OTP";

        if (detail.includes("locked")) {
          setMsg("msg", "🔒 " + detail, "err");
        }
        else if (detail.includes("Too many")) {
          setMsg("msg", "⚠️ " + detail, "err");
        }
        else {
          setMsg("msg", detail, "err");
        }

        return;
      }

      localStorage.setItem(
        "token",
        data.access_token
      );

      localStorage.removeItem("otp_mode");
      localStorage.removeItem("login_email");

      window.location.href =
        "/static/dashboard.html";
    }

  } catch (e) {
    setMsg(
      "msg",
      "Unable to connect to server",
      "err"
    );
  }
}


// ======================================================
// AUTH HELPERS
// ======================================================

function requireAuth() {
  const token = localStorage.getItem("token");

  if (!token) {
    window.location.href = "/";
  }
}

function logout() {
  localStorage.clear();
  window.location.href = "/";
}


// ======================================================
// NAV HELPERS
// ======================================================

function goSignup() {
  window.location.href =
    "/static/signup.html";
}

function goLogin() {
  window.location.href = "/";
}


// ======================================================
// DASHBOARD NAVIGATION
// ======================================================

function goNotes() {
  requireAuth();
  window.location.href =
    "/static/notes.html";
}

function goTodos() {
  requireAuth();
  window.location.href =
    "/static/todos.html";
}

function goPasswords() {
  requireAuth();
  window.location.href =
    "/static/passwords.html";
}

function goPqc() {
  requireAuth();
  window.location.href =
    "/static/pqc.html";
}
```
