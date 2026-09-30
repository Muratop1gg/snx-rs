const $ = (id) => document.getElementById(id);

let lastStatusKind = null;

function log(msg) {
    const el = $("log");
    const t = new Date().toLocaleTimeString();
    el.textContent += `[${t}] ${msg}\n`;
    el.scrollTop = el.scrollHeight;
}

async function api(path, opts = {}) {
    const res = await fetch(`/api${path}`, {
        headers: { "Content-Type": "application/json" },
        ...opts,
    });
    try {
        return await res.json();
    } catch (e) {
        return { ok: false, error: `HTTP ${res.status}` };
    }
}

function setBadge(kind) {
    const el = $("status-badge");
    el.className = `badge badge-${kind}`;
    const labels = {
        disconnected: "Отключено",
        connecting: "Подключение…",
        connected: "Подключено",
        mfa: "Ожидает MFA",
        unknown: "…",
    };
    el.textContent = labels[kind] || kind;
}

function renderStatus(data) {
    const details = $("status-details");
    details.innerHTML = "";

    if (!data.ok) {
        details.innerHTML = `<dt>Ошибка</dt><dd>${data.error ?? "неизвестно"}</dd>`;
        setBadge("unknown");
        return;
    }

    const s = data.status;
    setBadge(s.kind);

    if (s.kind === "connected") {
        const add = (k, v) => {
            const dt = document.createElement("dt");
            dt.textContent = k;
            const dd = document.createElement("dd");
            dd.textContent = v ?? "—";
            details.append(dt, dd);
        };
        add("Профиль", s.profile);
        add("Сервер", s.server);
        add("Пользователь", s.user);
        add("IP", s.ip);
        add("С", s.since);
    } else if (s.kind === "mfa") {
        const add = (k, v) => {
            const dt = document.createElement("dt");
            dt.textContent = k;
            const dd = document.createElement("dd");
            dd.textContent = v ?? "—";
            details.append(dt, dd);
        };
        add("Тип", s.mfa_type);
        add("Запрос", s.prompt);
    } else if (s.kind === "connecting") {
        details.innerHTML = `<dt>Состояние</dt><dd>Идёт подключение…</dd>`;
    }

    renderChallenge(data.pending);
}

function renderChallenge(pending) {
    const card = $("challenge-card");
    if (!pending) {
        card.classList.add("hidden");
        return;
    }
    card.classList.remove("hidden");
    $("challenge-prompt").textContent = pending.header
        ? `${pending.header}: ${pending.prompt}`
        : pending.prompt;
    const inp = $("challenge-answer");
    inp.type = pending.secure ? "password" : "text";
    inp.placeholder = pending.default_entry ?? "";
    inp.focus();
}

async function refresh() {
    const data = await api("/status");
    renderStatus(data);
    if (data.status && data.status.kind !== lastStatusKind) {
        lastStatusKind = data.status.kind;
        log(`Статус: ${data.status.kind}`);
    }
}

async function loadProfiles() {
    const data = await api("/profiles");
    const list = $("profiles-list");
    const sel = $("profile");

    list.innerHTML = "";
    if (sel) sel.innerHTML = "";

    if (!data.ok || !data.profiles.length) {
        list.innerHTML = `<li><span class="profile-meta">— нет профилей —</span></li>`;
        if (sel) sel.innerHTML = `<option value="">— нет профилей —</option>`;
        return;
    }

    for (const p of data.profiles) {
        // В список
        const li = document.createElement("li");

        const info = document.createElement("div");
        info.innerHTML = `
      <div><strong>${escapeHtml(p.name)}</strong></div>
      <div class="profile-meta">${escapeHtml(p.server || "—")} · ${escapeHtml(p.user || "—")} · ${p.tunnel_type}</div>
    `;

        const del = document.createElement("button");
        del.className = "danger";
        del.textContent = "Удалить";
        del.addEventListener("click", () => deleteProfile(p.id, p.name));

        li.append(info, del);
        list.appendChild(li);
        if (sel) {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = `${p.name} (${p.server || "?"})`;
            sel.appendChild(opt);
        }
    }
}

function escapeHtml(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
}

async function createProfile() {
    const body = {
        name: $("new-name").value.trim(),
        server: $("new-server").value.trim(),
        ignore_server_cert: $("new-ignore-cert").checked,
        user: $("new-user").value,
        password: $("new-password").value,
        tunnel_type: $("new-tunnel-type").value,
        login_type: $("new-login-type").value,
        keychain: $("new-keychain").checked,
        default_route: $("new-default-route").checked,
        no_dns: $("new-no-dns").checked,
    };

    if (!body.name || !body.server) {
        log("Имя и сервер обязательны");
        return;
    }

    log(`Создание профиля: ${body.name}`);
    const data = await api("/profiles", { method: "POST", body: JSON.stringify(body) });
    if (!data.ok) {
        log(`Ошибка: ${data.error}`);
        return;
    }

    log(`Профиль создан: ${data.id}`);
    // Очищаем форму
    for (const id of ["new-name","new-server","new-user","new-password","new-login-type"]) {
        $(id).value = "";
    }
    $("new-keychain").checked = false;
    $("new-default-route").checked = false;
    $("new-no-dns").checked = false;

    await loadProfiles();
}

async function deleteProfile(id, name) {
    if (!confirm(`Удалить профиль «${name}»?`)) return;
    log(`Удаление профиля: ${name}`);
    const data = await api(`/profiles/${id}`, { method: "DELETE" });
    if (!data.ok) {
        log(`Ошибка: ${data.error}`);
        return;
    }
    log(`Профиль удалён`);
    await loadProfiles();
}

async function connect() {
    const profile = $("profile").value;
    if (!profile) return;
    const body = {
        profile,
        password: $("password").value || null,
        mfa_code: $("mfa").value || null,
    };
    log(`Connect → ${profile}`);
    const data = await api("/connect", { method: "POST", body: JSON.stringify(body) });
    if (!data.ok) log(`Ошибка: ${data.error}`);
    else log(`OK: ${data.status.kind}`);
    await refresh();
}

async function disconnect() {
    log("Disconnect");
    const data = await api("/disconnect", { method: "POST" });
    if (!data.ok) log(`Ошибка: ${data.error}`);
    await refresh();
}

async function reconnect() {
    log("Reconnect");
    const data = await api("/reconnect", { method: "POST" });
    if (!data.ok) log(`Ошибка: ${data.error}`);
    await refresh();
}

async function submitChallenge() {
    const answer = $("challenge-answer").value;
    const data = await api("/challenge", {
        method: "POST",
        body: JSON.stringify({ answer }),
    });
    if (!data.ok) log(`Ошибка challenge: ${data.error}`);
    else log("Ответ отправлен");
    $("challenge-answer").value = "";
}

async function cancelChallenge() {
    await api("/challenge/cancel", { method: "POST" });
    log("Ввод отменён");
}

document.addEventListener("DOMContentLoaded", async () => {
    const on = (id, event, fn) => {
        const el = $(id);
        if (el) el.addEventListener(event, fn);
    };

    on("btn-connect", "click", connect);
    on("btn-disconnect", "click", disconnect);
    on("btn-reconnect", "click", reconnect);
    on("btn-challenge-submit", "click", submitChallenge);
    on("btn-challenge-cancel", "click", cancelChallenge);
    on("btn-create-profile", "click", createProfile);
    on("challenge-answer", "keydown", (e) => {
        if (e.key === "Enter") submitChallenge();
    });

    await loadProfiles();
    await refresh();
    setInterval(refresh, 2000);
});