// ======================================================
// SecureVault Authentication Logic (FINAL STABLE VERSION)
// Full Replaceable Code
// Fixes:
// - Account lock popup
// - Wrong password popup
// - Remaining attempts display (2/3, 1/3)
// - Network error false alerts
// - Buttons freezing after account lock
// - Stale localStorage cleanup
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
// CLEAR TEMP AUTH STATE
// ======================================================

function clearTempAuthState() {
  localStorage.removeItem("otp_mode");
  localStorage.removeItem("login_email");
  localStorage.removeItem("signup_email");
}


// ======================================================
// SAFE JSON PARSER
// ======================================================

async function safeJson(
  res,
  fallbackMessage = "Server error"
) {
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
      clearTempAuthState();

      setMsg(
        "msg",
        "Email and password required",
        "err"
      );
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
      clearTempAuthState();

      const detail =
        data.detail || "Signup failed";

      if (detail.includes("locked")) {
        setMsg(
          "msg",
          "🔒 " + detail,
          "err"
        );
      }
      else if (detail.includes("Too many")) {
        setMsg(
          "msg",
          "⚠️ " + detail,
          "err"
        );
      }
      else {
        setMsg(
          "msg",
          detail,
          "err"
        );
      }

      return;
    }

    localStorage.setItem(
      "otp_mode",
      "signup"
    );

    localStorage.setItem(
      "signup_email",
      email
    );

    window.location.href =
      "/static/otp.html";

  } catch (e) {
    clearTempAuthState();

    setMsg(
      "msg",
      "Unable to connect to server",
      "err"
    );
  }
}


// ======================================================
// LOGIN
// ======================================================

async function login() {
  try {
    const email = qs("email")?.value?.trim();
    const password = qs("password")?.value;

    if (!email || !password) {
      clearTempAuthState();

      setMsg(
        "msg",
        "Email and password required",
        "err"
      );
      return;
    }

    setMsg(
      "msg",
      "Checking credentials..."
    );

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

    const data = await safeJson(
      res,
      "Login failed. Please try again."
    );

    if (!res.ok) {
      clearTempAuthState();

      const detail =
        data.detail || "Login failed";

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
      // TOO MANY REQUESTS
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
      // WRONG PASSWORD + REMAINING ATTEMPTS
      // IMPORTANT FIX
      // -----------------------------
      else if (
        detail.includes("Incorrect password")
      ) {
        setMsg(
          "msg",
          "❌ " + detail,
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

    localStorage.setItem(
      "otp_mode",
      "login"
    );

    localStorage.setItem(
      "login_email",
      email
    );

    window.location.href =
      "/static/otp.html";
  }

  catch (e) {
    clearTempAuthState();

    setMsg(
      "msg",
      "Unable to connect to server",
      "err"
    );
  }
}


// ======================================================
// VERIFY OTP
// ======================================================

async function verifyOtp() {
  try {
    const otp = qs("otp")?.value?.trim();
    const mode =
      localStorage.getItem("otp_mode");

    if (!otp || !mode) {
      clearTempAuthState();

      setMsg(
        "msg",
        "OTP session expired",
        "err"
      );
      return;
    }

    setMsg(
      "msg",
      "Verifying OTP..."
    );

    // ==================================================
    // SIGNUP OTP
    // ==================================================

    if (mode === "signup") {
      const email =
        localStorage.getItem(
          "signup_email"
        );

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
        clearTempAuthState();

        const detail =
          data.detail || "Invalid OTP";

        if (detail.includes("locked")) {
          setMsg(
            "msg",
            "🔒 " + detail,
            "err"
          );
        }
        else if (
          detail.includes("Too many")
        ) {
          setMsg(
            "msg",
            "⚠️ " + detail,
            "err"
          );
        }
        else {
          setMsg(
            "msg",
            detail,
            "err"
          );
        }

        return;
      }

      clearTempAuthState();

      setMsg(
        "msg",
        "Account verified ✅ Redirecting to login...",
        "ok"
      );

      setTimeout(() => {
        window.location.href = "/";
      }, 1200);

      return;
    }

    // ==================================================
    // LOGIN OTP
    // ==================================================

    if (mode === "login") {
      const email =
        localStorage.getItem(
          "login_email"
        );

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
        clearTempAuthState();

        const detail =
          data.detail || "Invalid OTP";

        if (detail.includes("locked")) {
          setMsg(
            "msg",
            "🔒 " + detail,
            "err"
          );
        }
        else if (
          detail.includes("Too many")
        ) {
          setMsg(
            "msg",
            "⚠️ " + detail,
            "err"
          );
        }
        else {
          setMsg(
            "msg",
            detail,
            "err"
          );
        }

        return;
      }

      localStorage.setItem(
        "token",
        data.access_token
      );

      localStorage.removeItem(
        "otp_mode"
      );

      localStorage.removeItem(
        "login_email"
      );

      window.location.href =
        "/static/dashboard.html";
    }

  } catch (e) {
    clearTempAuthState();

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
  const token =
    localStorage.getItem("token");

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
  clearTempAuthState();

  window.location.href =
    "/static/signup.html";
}

function goLogin() {
  clearTempAuthState();

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
