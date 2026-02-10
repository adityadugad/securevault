// ===============================
// PASSWORD VAULT LOGIC
// ===============================

async function loadPasswords() {
  // unchanged (your original logic can remain here if needed)
}

// -------------------------------
// SAVE PASSWORD (UNCHANGED)
// -------------------------------
async function savePassword() {
  const site = document.getElementById("site").value;
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const msg = document.getElementById("passMsg");
  const token = localStorage.getItem("token");

  if (!site || !username || !password) {
    msg.innerText = "All fields required";
    msg.className = "msg err";
    return;
  }

  const res = await fetch(
    `/vault/passwords?site=${encodeURIComponent(site)}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  if (!res.ok) {
    msg.innerText = "Failed to save password";
    msg.className = "msg err";
    return;
  }

  msg.innerText = "Encrypted password saved ✅";
  msg.className = "msg ok";

  document.getElementById("site").value = "";
  document.getElementById("username").value = "";
  document.getElementById("password").value = "";

  resetStrengthUI();
  loadPasswords();
}

// -------------------------------
// DELETE PASSWORD (UNCHANGED)
// -------------------------------
async function deletePassword(id) {
  const token = localStorage.getItem("token");

  await fetch(`/vault/passwords/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` }
  });

  loadPasswords();
}

// ===============================
// PASSWORD STRENGTH (REAL SVM)
// ===============================

async function checkPasswordStrength(pwd) {
  const token = localStorage.getItem("token");
  if (!pwd) {
    resetStrengthUI();
    return;
  }

  try {
    const res = await fetch("/vault/password-strength", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`
      },
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
  input.style.borderColor = "";
  text.innerText = "";
}
