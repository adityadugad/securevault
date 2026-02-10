// ===============================
// PASSWORD VAULT LOGIC
// ===============================

// -------------------------------
// LOAD PASSWORDS (RESTORED)
// -------------------------------
async function loadPasswords() {
  const token = localStorage.getItem("token");
  const list = document.getElementById("passwordsList");
  list.innerHTML = "";

  try {
    const res = await fetch("/vault/passwords/decrypted", {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.ok) return;

    const data = await res.json();

    data.passwords.forEach(p => {
      list.innerHTML += `
        <div class="card">
          <h4>🔐 ${p.site}</h4>
          <p class="muted">User: ${p.username}</p>
          <p><strong>Password:</strong> ${p.password}</p>
          <div class="kv">
            <span>Created</span>
            <span>${p.created_at}</span>
          </div>
          <button class="btn secondary" onclick="deletePassword(${p.id})">
            🗑 Delete
          </button>
        </div>
      `;
    });

  } catch (err) {
    console.error("Failed to load passwords", err);
  }
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

  } catch (err) {
    // silent fail (no UI break)
    console.error("Strength check failed", err);
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
  } else if (strength === "strong") {
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
