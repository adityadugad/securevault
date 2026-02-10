async function sendOTP() {
  const email = document.getElementById("email").value;
  const msg = document.getElementById("msg");

  if (!email) {
    msg.innerText = "Email is required";
    msg.className = "msg err";
    return;
  }

  const res = await fetch("/auth/reset-password?email=" + encodeURIComponent(email), {
    method: "POST"
  });

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

  const res = await fetch(
    `/auth/reset-password-confirm?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}&new_password=${encodeURIComponent(password)}`,
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
