// Mini App client for Remofy MFA.
// Lifecycle:
//   1. Verify Telegram initData against the backend → receive mfa_session cookie.
//   2. Hit /status to know whether the user is enrolled + has an active session.
//   3. Render setup / unlock / done accordingly.
// All /api/mfa/bot/* calls rely on the HttpOnly cookie minted in step 1.

const tg = window.Telegram && window.Telegram.WebApp;
const API_BASE = "/api/mfa/bot";
const REQUESTED_ACTION =
  new URLSearchParams(window.location.search).get("action") || "";
// localStorage key for the per-device PIN binding. The DeviceID is a
// random string the server generated when this device first set up a
// PIN; clearing it dissociates this Telegram install from any PIN row.
const PIN_DEVICE_KEY = "mfa_device_id";
let state = {
  enrolled: false,
  hasDevices: false,
  webauthnFailed: false, // set when auto-unlock can't find a credential on THIS device
  pinDevices: 0,
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
  state.pinDevices = status.pin_devices || 0;

  // Bot opened the Mini App via /bind: skip the unlock UI entirely and
  // land on the registration ceremony. Requires an active session — if
  // the user is locked we fall back to the unlock flow first, then bind
  // after success (set webauthnFailed so unlockTotp shows bind-device).
  if (REQUESTED_ACTION === "bind" && status.enrolled) {
    if (status.active) {
      showScreen("bind-device");
      return;
    }
    state.webauthnFailed = true; // forces bind prompt after TOTP unlock
  }

  if (!status.enrolled) {
    await startSetup();
    return;
  }
  if (status.active) {
    showScreen("done");
    return;
  }

  // If this Telegram install has a PIN bound to it (DeviceID in
  // localStorage AND a matching row server-side), prefer the PIN unlock
  // path — it's the smoothest mobile UX and what the user explicitly
  // opted into. Fall back to TOTP/WebAuthn if the binding is stale.
  if (localStorage.getItem(PIN_DEVICE_KEY) && state.pinDevices > 0) {
    showPinUnlockScreen();
    return;
  }

  showUnlockScreen();
}

function showUnlockScreen() {
  showScreen("unlock");
  // If a PIN binding exists for this Telegram install, expose the
  // "PIN bilan kirish" button so the user can flip to PIN unlock without
  // going through TOTP. Hidden when no binding is registered here.
  const pinBtn = document.getElementById("switch-to-pin-btn");
  if (pinBtn) {
    pinBtn.style.display =
      localStorage.getItem(PIN_DEVICE_KEY) && state.pinDevices > 0
        ? ""
        : "none";
  }
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
  // Offer biometric first (strongest factor). If WebAuthn isn't available
  // in this WebView, fall straight to the PIN setup so the user still
  // has a faster-than-TOTP unlock path next time.
  if (
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials !== "undefined"
  ) {
    showScreen("bind-device");
  } else if (!localStorage.getItem(PIN_DEVICE_KEY)) {
    showPinSetupScreen();
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
  // User dismissed the biometric prompt — offer PIN setup as the
  // mobile-friendly fallback so they're not stuck typing TOTP forever.
  if (!localStorage.getItem(PIN_DEVICE_KEY)) {
    showPinSetupScreen();
  } else {
    showScreen("done");
  }
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
    // Post-unlock UX, in priority order:
    //   1. Offer to register a passkey for this device when WebAuthn is
    //      supported and no credential lives here yet.
    //   2. Otherwise offer to set a local PIN — works on every mobile
    //      Telegram WebView and matches the wallet-style flow users know.
    //   3. Otherwise just show "done".
    const supportsWA =
      typeof window.PublicKeyCredential !== "undefined" &&
      typeof navigator.credentials !== "undefined";
    const hasPinHere = !!localStorage.getItem(PIN_DEVICE_KEY);
    if (supportsWA) {
      showScreen("bind-device");
    } else if (!hasPinHere) {
      showPinSetupScreen();
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

// ===== PIN =====

function showPinUnlockScreen() {
  showScreen("pin-unlock");
  setTimeout(() => document.getElementById("pin-input").focus(), 120);
}

async function unlockPin() {
  const btn = document.getElementById("pin-unlock-btn");
  const input = document.getElementById("pin-input");
  const errEl = document.getElementById("pin-error");
  errEl.textContent = "";
  const pin = (input.value || "").trim();
  if (!/^\d{4,8}$/.test(pin)) {
    errEl.textContent = "PIN 4-8 raqamdan iborat bo'lishi kerak";
    return;
  }
  const deviceID = localStorage.getItem(PIN_DEVICE_KEY);
  if (!deviceID) {
    // localStorage cleared between page loads — drop to TOTP and offer
    // PIN setup again after unlock.
    switchToTotpFromPin();
    return;
  }
  btn.disabled = true;
  try {
    const resp = await fetch(`${API_BASE}/pin/unlock`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: deviceID, pin }),
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 429 && data.error === "locked") {
      errEl.textContent =
        "Juda ko'p urinish. " +
        (data.retry_seconds || 300) +
        " soniyadan keyin qayta urinib ko'ring.";
      return;
    }
    if (!resp.ok) {
      if (data.error === "unknown_device") {
        // The server doesn't know this DeviceID — local storage is out of
        // sync with reality. Forget it and switch to TOTP.
        localStorage.removeItem(PIN_DEVICE_KEY);
        switchToTotpFromPin();
        return;
      }
      errEl.textContent = "Noto'g'ri PIN";
      input.value = "";
      input.focus();
      return;
    }
    showScreen("done");
  } catch (e) {
    errEl.textContent = e.message || "Xatolik";
  } finally {
    btn.disabled = false;
  }
}

function switchToTotpFromPin() {
  document.getElementById("unlock-help").textContent =
    "Authenticator ilovasidan 6-xonali kodni kiriting.";
  showScreen("unlock");
  document.getElementById("unlock-webauthn").classList.add("hidden");
  document.getElementById("unlock-totp").classList.remove("hidden");
  setTimeout(() => document.getElementById("unlock-code").focus(), 120);
}

function forgetPinDevice() {
  localStorage.removeItem(PIN_DEVICE_KEY);
  switchToTotpFromPin();
}

function showPinSetupScreen() {
  showScreen("pin-setup");
  setTimeout(() => document.getElementById("pin-new").focus(), 120);
}

async function savePin() {
  const btn = document.getElementById("pin-save-btn");
  const errEl = document.getElementById("pin-setup-error");
  const a = document.getElementById("pin-new").value.trim();
  const b = document.getElementById("pin-confirm").value.trim();
  errEl.textContent = "";
  if (!/^\d{4,8}$/.test(a)) {
    errEl.textContent = "PIN 4-8 raqamdan iborat bo'lishi kerak";
    return;
  }
  if (a !== b) {
    errEl.textContent = "PIN'lar bir xil emas";
    return;
  }
  btn.disabled = true;
  try {
    const data = await fetchJSON(`${API_BASE}/pin/register`, {
      method: "POST",
      body: JSON.stringify({ pin: a, label: guessDeviceLabel() }),
    });
    if (data.device_id) {
      localStorage.setItem(PIN_DEVICE_KEY, data.device_id);
    }
    showScreen("done");
  } catch (e) {
    errEl.textContent = e.message || "Saqlanmadi";
  } finally {
    btn.disabled = false;
  }
}

function skipPinSetup() {
  showScreen("done");
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
