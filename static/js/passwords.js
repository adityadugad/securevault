// ===============================
// PASSWORD VAULT LOGIC
// ===============================

async function loadPasswords() {
  const token = localStorage.getItem("token");

  const res = await fetch("/vault/passwords/decrypted", {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) return;

  const data = await res.json();
  const list = document.getElementById("passwordsList");
  list.innerHTML = "";

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
}

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

  loadPasswords();
}

async function deletePassword(id) {
  const token = localStorage.getItem("token");

  await fetch(`/vault/passwords/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` }
  });

  loadPasswords();
}
