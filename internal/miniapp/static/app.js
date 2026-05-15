// Mini App client for Remofy MFA.
// Lifecycle:
//   1. Verify Telegram initData against the backend → receive mfa_session cookie.
//   2. Hit /status to know whether the user is enrolled + has an active session.
//   3. Render setup / unlock / done accordingly.
// All /api/mfa/bot/* calls rely on the HttpOnly cookie minted in step 1.

const tg = window.Telegram && window.Telegram.WebApp;
const API_BASE = "/api/mfa/bot";
let state = {
  enrolled: false,
  hasDevices: false,
  webauthnFailed: false, // set when auto-unlock can't find a credential on THIS device
  recoveryCodes: [],
};

if (tg) {
  tg.ready();
  tg.expand();
}

document.addEventListener("DOMContentLoaded", () => {
  bootstrap().catch((err) => {
    console.error(err);
    document.getElementById("screen-loading").innerHTML =
      `<p style="color:#ef4444">Xatolik: ${escapeHTML(err.message || "noma'lum")}</p>`;
  });
});

async function bootstrap() {
  if (!tg || !tg.initData) {
    throw new Error("Telegram ichida ochilishi kerak");
  }

  const verifyResp = await fetch(`/api/mfa/verify-telegram`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ init_data: tg.initData }),
  });

  if (verifyResp.status === 409) {
    showScreen("not-linked");
    return;
  }
  if (!verifyResp.ok) {
    throw new Error(`Tasdiqlash o'tmadi: ${verifyResp.status}`);
  }

  const status = await fetchJSON(`${API_BASE}/status`, { method: "POST" });
  state.enrolled = !!status.enrolled;
  state.hasDevices = (status.devices || 0) > 0;

  if (!status.enrolled) {
    await startSetup();
  } else if (status.active) {
    showScreen("done");
  } else {
    showUnlockScreen();
  }
}

function showUnlockScreen() {
  showScreen("unlock");
  // If the browser supports WebAuthn AND the user has at least one registered
  // credential (somewhere — maybe another device), try the biometric path.
  // If it fails (this device has no matching passkey) fall back to TOTP.
  const supportsWA =
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials !== "undefined";
  const wa = document.getElementById("unlock-webauthn");
  const totp = document.getElementById("unlock-totp");
  const help = document.getElementById("unlock-help");
  if (supportsWA && state.hasDevices) {
    wa.classList.remove("hidden");
    totp.classList.add("hidden");
    help.textContent = "Biometrik bilan kirish — qurilmangiz unlock'i so'raladi.";
    setTimeout(tryAutoUnlock, 150);
  } else {
    wa.classList.add("hidden");
    totp.classList.remove("hidden");
    setTimeout(() => document.getElementById("unlock-code").focus(), 120);
  }
}

async function tryAutoUnlock() {
  // Auto-call navigator.credentials.get without the manual-click error
  // pipeline. On failure (no passkey on THIS device, user cancelled,
  // browser blocks unsolicited prompt) flip the unlock screen to TOTP
  // with a translated explanation.
  try {
    const begin = await fetchJSON(`${API_BASE}/webauthn/login/begin`, { method: "POST" });
    const opts = prepareGetOptions(begin.options);
    const cred = await navigator.credentials.get({ publicKey: opts });
    if (!cred) throw new Error("cancelled");
    await fetchJSON(`${API_BASE}/webauthn/login/finish`, {
      method: "POST",
      body: JSON.stringify({
        handle: begin.handle,
        body: serializeAssertion(cred),
      }),
    });
    showScreen("done");
  } catch (e) {
    state.webauthnFailed = true;
    fallBackToTotp(e);
  }
}

function fallBackToTotp(reason) {
  document.getElementById("unlock-webauthn").classList.add("hidden");
  document.getElementById("unlock-totp").classList.remove("hidden");
  document.getElementById("unlock-help").textContent =
    "Bu qurilmada biometrik kalit topilmadi. TOTP kodi bilan kiring — kirgandan keyin shu qurilmani ham bog'lashingiz mumkin.";
  setTimeout(() => document.getElementById("unlock-code").focus(), 120);
}

function showTotpUnlock() {
  document.getElementById("unlock-webauthn").classList.add("hidden");
  document.getElementById("unlock-totp").classList.remove("hidden");
  document.getElementById("unlock-help").textContent =
    "Authenticator ilovasidan 6-xonali kodni kiriting.";
  setTimeout(() => document.getElementById("unlock-code").focus(), 120);
}

async function startSetup() {
  const setup = await fetchJSON(`${API_BASE}/totp/setup`, { method: "POST" });
  document.getElementById("qr-img").src = setup.qr_data_url;
  document.getElementById("secret-text").textContent = setup.secret;
  showScreen("setup");
}

function showVerifyEnroll() {
  showScreen("verify-enroll");
  setTimeout(() => document.getElementById("enroll-code").focus(), 120);
}

async function verifyEnroll() {
  const btn = document.getElementById("enroll-btn");
  const code = document.getElementById("enroll-code").value.trim();
  const errEl = document.getElementById("enroll-error");
  errEl.textContent = "";
  if (!/^\d{6}$/.test(code)) {
    errEl.textContent = "Kod 6 raqamdan iborat bo'lishi kerak";
    return;
  }
  btn.disabled = true;
  try {
    const data = await fetchJSON(`${API_BASE}/totp/verify`, {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    if (data.recovery_codes && data.recovery_codes.length) {
      state.recoveryCodes = data.recovery_codes;
      renderRecoveryCodes(data.recovery_codes);
      // After the user acknowledges the recovery codes we'll prompt for
      // biometric binding; bindDevice() lives below.
      const finishBtn = document.querySelector("#screen-recovery button.secondary");
      if (finishBtn) finishBtn.onclick = afterRecoveryAck;
      showScreen("recovery");
    } else {
      showScreen("done");
    }
  } catch (e) {
    errEl.textContent = e.message || "Noto'g'ri kod";
  } finally {
    btn.disabled = false;
  }
}

function afterRecoveryAck() {
  // Offer to bind the current device biometrically. Falls back to "done"
  // if WebAuthn isn't available (e.g. older mobile Telegram WebViews).
  if (
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials !== "undefined"
  ) {
    showScreen("bind-device");
  } else {
    showScreen("done");
  }
}

function renderRecoveryCodes(codes) {
  const list = document.getElementById("recovery-list");
  list.innerHTML = "";
  for (const c of codes) {
    const el = document.createElement("code");
    el.textContent = c;
    list.appendChild(el);
  }
}

function downloadRecovery() {
  const blob = new Blob(
    [
      "Remofy recovery codes\n",
      "Generated: " + new Date().toISOString() + "\n",
      "Each code works once. Keep this file safe.\n\n",
      state.recoveryCodes.join("\n") + "\n",
    ],
    { type: "text/plain" }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "remofy-recovery-codes.txt";
  a.click();
  URL.revokeObjectURL(url);
}

function finishEnroll() {
  showScreen("done");
}

async function unlockTotp() {
  const btn = document.getElementById("unlock-btn");
  const code = document.getElementById("unlock-code").value.trim();
  const errEl = document.getElementById("unlock-error");
  errEl.textContent = "";
  if (!/^\d{6}$/.test(code)) {
    errEl.textContent = "Kod 6 raqamdan iborat bo'lishi kerak";
    return;
  }
  btn.disabled = true;
  try {
    await fetchJSON(`${API_BASE}/totp/verify`, {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    // Offer to bind a passkey on THIS device after every TOTP unlock,
    // as long as the platform supports WebAuthn. We can't reliably tell
    // whether this specific device already has a credential (passkeys
    // are per-device, not per-user) — if the user used TOTP, it's a
    // safe bet biometric on this device would help. The bind screen has
    // a "Keyingi safar" button for users who don't want to bind.
    const supportsWA =
      typeof window.PublicKeyCredential !== "undefined" &&
      typeof navigator.credentials !== "undefined";
    if (supportsWA) {
      showScreen("bind-device");
    } else {
      showScreen("done");
    }
  } catch (e) {
    errEl.textContent = e.message || "Noto'g'ri kod";
  } finally {
    btn.disabled = false;
  }
}

function showRecoveryInput() {
  showScreen("recovery-input");
  setTimeout(() => document.getElementById("recovery-input").focus(), 120);
}

async function unlockRecovery() {
  const code = document.getElementById("recovery-input").value.trim();
  const errEl = document.getElementById("recovery-error");
  errEl.textContent = "";
  if (!code) {
    errEl.textContent = "Kod kiriting";
    return;
  }
  try {
    await fetchJSON(`${API_BASE}/recovery/use`, {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    showScreen("done");
  } catch (e) {
    errEl.textContent = e.message || "Noto'g'ri kod";
  }
}

// ===== WebAuthn =====

// b64uToBuf decodes a base64url-encoded string into an ArrayBuffer for the
// WebAuthn API. go-webauthn emits base64url without padding.
function b64uToBuf(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Convert the server-issued PublicKeyCredentialCreationOptions JSON shape
// into the typed-array shape navigator.credentials.create expects.
function prepareCreateOptions(opts) {
  const o = opts.publicKey || opts;
  o.challenge = b64uToBuf(o.challenge);
  o.user.id = b64uToBuf(o.user.id);
  if (Array.isArray(o.excludeCredentials)) {
    o.excludeCredentials = o.excludeCredentials.map((c) => ({
      ...c,
      id: b64uToBuf(c.id),
    }));
  }
  return o;
}

function prepareGetOptions(opts) {
  const o = opts.publicKey || opts;
  o.challenge = b64uToBuf(o.challenge);
  if (Array.isArray(o.allowCredentials)) {
    o.allowCredentials = o.allowCredentials.map((c) => ({
      ...c,
      id: b64uToBuf(c.id),
    }));
  }
  return o;
}

function serializeAttestation(cred) {
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults
      ? cred.getClientExtensionResults()
      : {},
  };
}

function serializeAssertion(cred) {
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle
        ? bufToB64u(cred.response.userHandle)
        : null,
    },
    clientExtensionResults: cred.getClientExtensionResults
      ? cred.getClientExtensionResults()
      : {},
  };
}

async function bindDevice() {
  const btn = document.getElementById("bind-btn");
  const errEl = document.getElementById("bind-error");
  errEl.textContent = "";
  btn.disabled = true;
  try {
    const begin = await fetchJSON(`${API_BASE}/webauthn/register/begin`, {
      method: "POST",
    });
    const opts = prepareCreateOptions(begin.options);
    const cred = await navigator.credentials.create({ publicKey: opts });
    if (!cred) throw new Error("Bekor qilindi");

    const label = guessDeviceLabel();
    await fetchJSON(`${API_BASE}/webauthn/register/finish`, {
      method: "POST",
      body: JSON.stringify({
        handle: begin.handle,
        body: serializeAttestation(cred),
        label,
      }),
    });
    showScreen("done");
  } catch (e) {
    errEl.textContent = e.message || "Bog'lash o'tmadi";
  } finally {
    btn.disabled = false;
  }
}

async function unlockWebAuthn() {
  const btn = document.getElementById("webauthn-btn");
  const errEl = document.getElementById("webauthn-error");
  errEl.textContent = "";
  btn.disabled = true;
  try {
    const begin = await fetchJSON(`${API_BASE}/webauthn/login/begin`, {
      method: "POST",
    });
    const opts = prepareGetOptions(begin.options);
    const cred = await navigator.credentials.get({ publicKey: opts });
    if (!cred) throw new Error("Bekor qilindi");

    await fetchJSON(`${API_BASE}/webauthn/login/finish`, {
      method: "POST",
      body: JSON.stringify({
        handle: begin.handle,
        body: serializeAssertion(cred),
      }),
    });
    showScreen("done");
  } catch (e) {
    errEl.textContent = e.message || "Tasdiqlash o'tmadi";
  } finally {
    btn.disabled = false;
  }
}

function guessDeviceLabel() {
  const ua = navigator.userAgent || "";
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android";
  if (/Macintosh/.test(ua)) return "Mac";
  if (/Windows/.test(ua)) return "Windows";
  return "passkey";
}

function closeApp() {
  if (tg && tg.close) {
    tg.close();
  } else {
    window.close();
  }
}

function showScreen(name) {
  for (const el of document.querySelectorAll(".card")) {
    el.classList.add("hidden");
  }
  const target = document.getElementById("screen-" + name);
  if (target) target.classList.remove("hidden");
}

async function fetchJSON(url, opts = {}) {
  const headers = Object.assign(
    { "Content-Type": "application/json" },
    opts.headers || {}
  );
  const resp = await fetch(url, {
    method: opts.method || "GET",
    credentials: "include",
    headers,
    body: opts.body,
  });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try {
      const j = await resp.json();
      if (j.error) msg = j.error;
    } catch (_) {}
    throw new Error(msg);
  }
  return resp.json();
}

function escapeHTML(s) {
  return String(s).replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[c])
  );
}
