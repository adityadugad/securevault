// ===============================
// SEND OTP (UNCHANGED LOGIC)
// ===============================
async function sendOTP() {
  const email = document.getElementById("email").value;
  const msg = document.getElementById("msg");

  if (!email) {
    msg.innerText = "Email is required";
    msg.className = "msg err";
    return;
  }

  const res = await fetch(
    "/auth/reset-password?email=" + encodeURIComponent(email),
    { method: "POST" }
  );

  if (!res.ok) {
    msg.innerText = "Failed to send OTP";
    msg.className = "msg err";
    return;
  }

  msg.innerText = "OTP sent to email ✅";
  msg.className = "msg ok";

  setTimeout(() => {
    window.location.href = "/static/reset-password.html";
  }, 1200);
}

// ===============================
// RESET PASSWORD (UPDATED SAFELY)
// ===============================
async function resetPassword() {
  const email = document.getElementById("email").value;
  const otp = document.getElementById("otp").value;
  const password = document.getElementById("password").value;
  const msg = document.getElementById("msg");

  if (!email || !otp || !password) {
    msg.innerText = "All fields required";
    msg.className = "msg err";
    return;
  }

  // 🔐 ENFORCE PASSWORD RULES (SAME AS SIGNUP)
  const strong =
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /[^A-Za-z0-9]/.test(password);

  if (!strong) {
    msg.innerText =
      "Password must contain 8+ characters, uppercase, lowercase, and special character.";
    msg.className = "msg err";
    return;
  }

  const res = await fetch(
    `/auth/reset-password-confirm?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(
      otp
    )}&new_password=${encodeURIComponent(password)}`,
    { method: "POST" }
  );

  if (!res.ok) {
    msg.innerText = "Invalid OTP or expired";
    msg.className = "msg err";
    return;
  }

  msg.innerText = "Password reset successful ✅";
  msg.className = "msg ok";

  setTimeout(() => {
    window.location.href = "/static/index.html";
  }, 1500);
}

// ===============================
// PASSWORD STRENGTH (SVM – LIVE)
// ===============================
async function checkPasswordStrength(pwd) {
  if (!pwd) {
    resetStrengthUI();
    return;
  }

  try {
    const res = await fetch("/vault/password-strength", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pwd })
    });

    if (!res.ok) return;

    const data = await res.json();
    applyStrengthUI(data.strength);
  } catch {
    // silent fail (no UI break)
  }
}

function applyStrengthUI(strength) {
  const input = document.getElementById("password");
  const text = document.getElementById("strengthText");

  if (!input || !text) return;

  if (strength === "weak") {
    input.style.borderColor = "#ef4444";
    text.innerText = "Password strength: Weak";
    text.style.color = "#ef4444";
  } else if (strength === "medium") {
    input.style.borderColor = "#facc15";
    text.innerText = "Password strength: Medium";
    text.style.color = "#facc15";
  } else {
    input.style.borderColor = "#22c55e";
    text.innerText = "Password strength: Strong";
    text.style.color = "#22c55e";
  }
}

function resetStrengthUI() {
  const input = document.getElementById("password");
  const text = document.getElementById("strengthText");
  if (!input || !text) return;
  input.style.borderColor = "";
  text.innerText = "";
}
