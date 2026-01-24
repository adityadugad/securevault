// ======================================================
// SecureVault Notes Logic (SAVE + LOAD + DELETE)
// ======================================================

function getToken() {
  return localStorage.getItem("token");
}

// ---------------- LOAD NOTES ----------------
async function loadNotes() {
  const token = getToken();
  if (!token) return;

  const res = await fetch("/vault/notes/decrypted", {
    headers: {
      "Authorization": "Bearer " + token
    }
  });

  const data = await res.json();
  const list = document.getElementById("notesList");
  list.innerHTML = "";

  if (!data.notes || data.notes.length === 0) {
    list.innerHTML = `<p class="muted">No notes yet</p>`;
    return;
  }

  data.notes.forEach(note => {
    const card = document.createElement("div");
    card.className = "card";

    card.innerHTML = `
      <h4>${note.title}</h4>
      <p class="muted">${note.content}</p>

      <div class="row" style="margin-top:10px">
        <button class="btn secondary" onclick="deleteNote(${note.id})">
          🗑 Delete
        </button>
      </div>
    `;

    list.appendChild(card);
  });
}

// ---------------- SAVE NOTE ----------------
async function saveNote() {
  const title = document.getElementById("noteTitle").value;
  const content = document.getElementById("noteContent").value;
  const msg = document.getElementById("noteMsg");

  if (!title || !content) {
    msg.innerText = "Title and content required";
    msg.className = "msg err";
    return;
  }

  const res = await fetch(
    `/vault/notes?title=${encodeURIComponent(title)}&content=${encodeURIComponent(content)}`,
    {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + getToken()
      }
    }
  );

  if (!res.ok) {
    msg.innerText = "Failed to save note";
    msg.className = "msg err";
    return;
  }

  msg.innerText = "Encrypted note saved ✅";
  msg.className = "msg ok";

  document.getElementById("noteTitle").value = "";
  document.getElementById("noteContent").value = "";

  loadNotes();
}

// ---------------- DELETE NOTE ----------------
async function deleteNote(id) {
  if (!confirm("Delete this note permanently?")) return;

  const res = await fetch(`/vault/notes/${id}`, {
    method: "DELETE",
    headers: {
      "Authorization": "Bearer " + getToken()
    }
  });

  if (!res.ok) {
    alert("Failed to delete note");
    return;
  }

  loadNotes();
}
