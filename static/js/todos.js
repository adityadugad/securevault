// ===============================
// TO-DO LOGIC (ENCRYPTED)
// ===============================

async function loadTodos() {
  const token = localStorage.getItem("token");

  const res = await fetch("/vault/todos/decrypted", {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) return;

  const data = await res.json();
  const list = document.getElementById("todosList");
  list.innerHTML = "";

  data.todos.forEach(todo => {
    list.innerHTML += `
      <div class="card">
        <h4>🗒 ${todo.task}</h4>
        <div class="kv">
          <span>Created</span>
          <span>${todo.created_at}</span>
        </div>
        <button class="btn secondary" onclick="deleteTodo(${todo.id})">
          🗑 Delete
        </button>
      </div>
    `;
  });
}

async function saveTodo() {
  const task = document.getElementById("todoTask").value;
  const msg = document.getElementById("todoMsg");
  const token = localStorage.getItem("token");

  if (!task) {
    msg.innerText = "Task required";
    msg.className = "msg err";
    return;
  }

  const res = await fetch(`/vault/todos?task=${encodeURIComponent(task)}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) {
    msg.innerText = "Failed to save task";
    msg.className = "msg err";
    return;
  }

  msg.innerText = "Encrypted task saved ✅";
  msg.className = "msg ok";
  document.getElementById("todoTask").value = "";
  loadTodos();
}

async function deleteTodo(id) {
  const token = localStorage.getItem("token");

  await fetch(`/vault/todos/${id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` }
  });

  loadTodos();
}
