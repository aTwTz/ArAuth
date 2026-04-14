// arauth 服务前端主逻辑（原生 JS，零构建）。
//
// 数据纪律（DESIGN.md 第 2 节）：localStorage 只写两类非秘密 hint 键——
//   arauth.has_credential      = "1"           本机注册/登录过（纯 UX）
//   arauth.identity.<handle>   = credentialId  identity→credential 映射
// 恢复码原文、TOTP setup/recovery token、secret、URI 一律只留在流程内存；
// 会话 token 根本到不了 JS：第一方会话使用 httpOnly cookie。
'use strict';

const HAS_CREDENTIAL = 'arauth.has_credential';
const IDENTITY_PREFIX = 'arauth.identity.';

// UiError 是面向用户的错误：message 直接显示，不暴露服务端细节
// （服务端失败响应本就不可区分，保密红线第 6 条）。
class UiError extends Error {}

const $ = (id) => document.getElementById(id);
const statusEl = $('status');

function status(msg, isError = false) {
  statusEl.textContent = msg;
  statusEl.className = isError ? 'error' : '';
}

const BUSY_BUTTONS = [
  'btn-register',
  'btn-login',
  'btn-recover',
  'btn-recover-totp',
  'btn-totp-begin',
  'btn-register-skip',
  'btn-manage-totp',
  'btn-totp-confirm',
  'btn-totp-close',
];

function setBusy(busy) {
  for (const id of BUSY_BUTTONS) $(id).disabled = busy;
}

// --- HTTP 封装 -----------------------------------------------------------

async function api(path, { method = 'POST', body, headers = {} } = {}) {
  let resp;
  try {
    resp = await fetch(path, {
      method,
      credentials: 'same-origin', // 只与同源 service-server 交换第一方 cookie
      headers: body !== undefined
        ? { ...headers, 'Content-Type': 'application/json' }
        : headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new UiError('无法连接服务后端，请检查网络后重试');
  }
  if (resp.ok) return resp.json();
  // 服务端错误词表只有 invalid / rate limited / internal，映射为对用户
  // 有意义的提示，不区分"哈希不匹配"与"记录不存在"。
  if (resp.status === 429) throw new UiError('请求太频繁，请稍后再试');
  if (resp.status === 403) throw new UiError('该身份尚未完成恢复码确认，请先完成注册确认');
  if (resp.status >= 500) throw new UiError('服务暂时不可用，请稍后再试');
  throw new UiError('凭证无效或已过期，请重试');
}

// --- PoW（Web Worker） ---------------------------------------------------

function runPowWorker(challenge, difficulty) {
  return new Promise((resolve, reject) => {
    const w = new Worker('pow-worker.js');
    w.onmessage = (e) => {
      if (e.data.nonce) {
        w.terminate();
        resolve(e.data.nonce);
      } else if (e.data.progress) {
        status(`正在计算工作量证明…（已尝试 ${e.data.progress} 次）`);
      }
    };
    w.onerror = () => {
      w.terminate();
      reject(new UiError('工作量证明计算失败，请刷新后重试'));
    };
    w.postMessage({ challenge, difficulty });
  });
}

async function solvePow() {
  const issued = await api('/pow/challenge', { method: 'GET' });
  status('正在计算工作量证明…');
  const nonce = await runPowWorker(issued.challenge, issued.difficulty);
  status('工作量证明完成');
  return { pow_challenge: issued.challenge, pow_nonce: nonce };
}

// --- WebAuthn 封装 -------------------------------------------------------

function mapCredentialError(e) {
  if (e && e.name === 'NotAllowedError') {
    return new UiError('操作已取消或超时，请重试');
  }
  if (e && e.name === 'InvalidStateError') {
    return new UiError('这个验证器已注册过，请直接登录');
  }
  return new UiError('创建/使用密钥失败，请更换验证器后重试');
}

async function createCredential(publicKeyJSON) {
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(publicKeyJSON);
  try {
    return await navigator.credentials.create({ publicKey });
  } catch (e) {
    throw mapCredentialError(e);
  }
}

async function getAssertion(publicKeyJSON) {
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(publicKeyJSON);
  try {
    return await navigator.credentials.get({ publicKey });
  } catch (e) {
    throw mapCredentialError(e);
  }
}

// --- hint（localStorage，仅 DESIGN.md 第 2 节允许的两类键） ---------------

function hasLocalCredential() {
  return localStorage.getItem(HAS_CREDENTIAL) === '1';
}

function knownIdentity(userHandle) {
  return localStorage.getItem(IDENTITY_PREFIX + userHandle) !== null;
}

function rememberIdentity(userHandle, credentialId) {
  localStorage.setItem(HAS_CREDENTIAL, '1');
  localStorage.setItem(IDENTITY_PREFIX + userHandle, credentialId);
}

// --- 全屏恢复码遮罩（强制勾选才可继续） -----------------------------------

function showRecoveryCode(code, confirmLabel) {
  return new Promise((resolve) => {
    const overlay = $('code-overlay');
    const checkbox = $('code-checkbox');
    const confirmBtn = $('code-confirm');
    $('code-text').textContent = code;
    checkbox.checked = false;
    confirmBtn.disabled = true;
    confirmBtn.textContent = confirmLabel;
    checkbox.onchange = () => { confirmBtn.disabled = !checkbox.checked; };
    confirmBtn.onclick = () => {
      overlay.hidden = true;
      // 原文确认后立即从 DOM 与控件状态中清掉，不留隐藏副本。
      $('code-text').textContent = '';
      checkbox.checked = false;
      checkbox.onchange = null;
      confirmBtn.onclick = null;
      resolve();
    };
    overlay.hidden = false;
  });
}

// --- "要不要沿用身份"询问框（纯告知 UI，两键都只是继续，DESIGN.md 第 4 节） ---

function askReuseIdentity() {
  return new Promise((resolve) => {
    const dialog = $('reuse-dialog');
    const done = () => { dialog.hidden = true; resolve(); };
    $('reuse-yes').onclick = done;
    $('reuse-no').onclick = done;
    dialog.hidden = false;
  });
}

// --- TOTP 绑定（注册时凭 rp_pending，登录后凭 rp_session） -----------------

// setup token 只存在这个流程变量中；secret 与 URI 只展示，不再复制到持久状态。
let activeTotpSetup = null;

function clearTotpEnrollment() {
  activeTotpSetup = null;
  $('totp-secret').textContent = '';
  $('totp-uri').textContent = '';
  $('totp-recovery-id').textContent = '';
  $('totp-code-input').value = '';
  $('totp-section').hidden = true;
}

async function beginTotpEnrollment(mode) {
  clearTotpEnrollment();
  status('正在获取 TOTP 绑定信息…');
  const result = await api(`/recovery/totp/enroll/begin?flow=${mode}`, { body: {} });
  activeTotpSetup = { setupToken: result.setup_token, mode };
  $('totp-title').textContent = mode === 'register' ? '绑定 TOTP（可选）' : '绑定或更换 TOTP';
  // 服务端返回的字符串一律按文本展示，不拼接 HTML。
  $('totp-secret').textContent = result.secret;
  $('totp-uri').textContent = result.otpauth_uri;
  $('totp-recovery-id').textContent = result.recovery_id;
  $('totp-section').hidden = false;
  status('请将绑定信息添加到身份验证器，并保存 recovery_id。');
}

async function confirmTotpEnrollment() {
  if (!activeTotpSetup) throw new UiError('绑定信息已失效，请重新获取');
  const code = $('totp-code-input').value.trim();
  if (!/^\d{6}$/.test(code)) throw new UiError('请输入 6 位数字动态码');
  const setup = activeTotpSetup;
  status('正在确认 TOTP 绑定…');
  await api(`/recovery/totp/enroll/confirm?flow=${setup.mode}`, {
    body: { setup_token: setup.setupToken, code },
  });
  // confirm 后 setup token 不再使用；即使后续注册确认失败，也先清掉秘密。
  clearTotpEnrollment();
  if (setup.mode === 'register') {
    await finishRegistration();
  } else {
    status('TOTP 绑定或更换完成。');
  }
}

function closeTotpEnrollment() {
  const mode = activeTotpSetup && activeTotpSetup.mode;
  clearTotpEnrollment();
  status(mode === 'register'
    ? '已取消本次 TOTP 绑定，可以重试或跳过并完成注册。'
    : '已取消本次 TOTP 绑定。');
}

// --- 注册与登录 -----------------------------------------------------------

async function register() {
  const pow = await solvePow();
  status('正在生成注册参数…');
  const options = await api('/register/options', { body: pow });
  status('请按系统提示创建密钥（指纹 / 面容 / PIN）…');
  const credential = await createCredential(options.publicKey);
  status('正在验证…');
  const result = await api('/register/verify', { body: credential.toJSON() });
  // 恢复码确认后还不能激活：先让用户明确选择绑定 TOTP 或跳过。
  await showRecoveryCode(result.recovery_code, '我已保存恢复码，继续');
  $('register-next-section').hidden = false;
  status('请选择绑定 TOTP（可选），或跳过并完成注册。');
}

async function finishRegistration() {
  status('正在确认激活…');
  await api('/register/confirm');
  clearTotpEnrollment();
  $('register-next-section').hidden = true;
  // 注册响应白名单不含 user_handle，identity→credential
  // 映射在首次登录断言（自带 userHandle）后写入；此处只写"本机有凭证"。
  localStorage.setItem(HAS_CREDENTIAL, '1');
  status('注册完成。现在可以登录了。');
  refreshHint();
}

async function login() {
  status('正在获取登录参数…');
  const options = await api('/login/options');
  status('请按系统提示验证身份…');
  const assertion = await getAssertion(options.publicKey);
  status('正在验证…');
  const cred = assertion.toJSON();
  await api('/login/verify', { body: cred });
  status('正在读取第一方会话身份…');
  const session = await api('/whoami', { method: 'GET' });
  // hint 缺失但断言成功 = 同步飘来的副本 → 弹"沿用身份"询问框（纯告知）。
  const synced = !knownIdentity(session.user_handle);
  rememberIdentity(session.user_handle, cred.id);
  if (synced) await askReuseIdentity();
  $('card-handle').textContent = session.user_handle;
  $('card-credential').textContent = cred.id;
  $('card-backed-up').textContent = session.backed_up ? '是（可跨设备同步）' : '否（仅本机）';
  $('identity-card').hidden = false;
  status('登录成功，已建立第一方会话。');
  refreshHint();
}

// --- 两种找回入口共用后续换钥流程 -----------------------------------------

async function finishRecovery(recoveryToken) {
  // 恢复凭证只活在内存变量里（一次性、5 分钟过期），不进 localStorage。
  const headers = { 'X-Arauth-Recovery-Token': recoveryToken };
  status('正在生成注册参数…');
  const options = await api('/recovery/options', { headers });
  status('请按系统提示创建新密钥…');
  const credential = await createCredential(options.publicKey);
  status('正在挂接新密钥并轮换恢复码…');
  const result = await api('/recovery/verify', { body: credential.toJSON(), headers });
  // 旧码已焚，新码原文只在这次响应里出现。
  await showRecoveryCode(result.recovery_code, '我已抄好新恢复码');
  localStorage.setItem(HAS_CREDENTIAL, '1');
  status('找回完成：新密钥已挂接，旧恢复码已作废。现在可以用新密钥登录。');
  refreshHint();
}

async function recoverWithCode() {
  const code = $('recovery-code-input').value.trim();
  if (!code) throw new UiError('请输入一次性恢复码');
  const pow = await solvePow();
  status('正在兑换恢复码…');
  const { recovery_token } = await api('/recovery/redeem', {
    body: { recovery_code: code, ...pow },
  });
  $('recovery-code-input').value = '';
  await finishRecovery(recovery_token);
}

async function recoverWithTotp() {
  const recoveryId = $('recovery-id-input').value.trim();
  const code = $('recovery-totp-code-input').value.trim();
  if (!recoveryId) throw new UiError('请输入 recovery_id');
  if (!/^\d{6}$/.test(code)) throw new UiError('请输入 6 位数字动态码');
  const pow = await solvePow();
  status('正在验证 TOTP 找回信息…');
  const { recovery_token } = await api('/recovery/totp/redeem', {
    body: { recovery_id: recoveryId, code, ...pow },
  });
  $('recovery-id-input').value = '';
  $('recovery-totp-code-input').value = '';
  await finishRecovery(recovery_token);
}

// --- 页面装配 -------------------------------------------------------------

function refreshHint() {
  $('hint-line').textContent = hasLocalCredential()
    ? '本机有已注册的凭证，可直接登录。'
    : '本机暂无凭证记录——可以注册新身份，或用恢复码或 TOTP 找回已有身份。';
}

function wire(id, fn) {
  $(id).addEventListener('click', async () => {
    setBusy(true);
    status('');
    try {
      await fn();
    } catch (e) {
      // ceremony 取消/失败与网络错误都落到状态栏，不白屏。
      status(e instanceof UiError ? e.message : '发生未知错误，请重试', true);
    } finally {
      setBusy(false);
    }
  });
}

if (window.PublicKeyCredential &&
    PublicKeyCredential.parseCreationOptionsFromJSON &&
    PublicKeyCredential.parseRequestOptionsFromJSON) {
  wire('btn-register', register);
  wire('btn-login', login);
  wire('btn-recover', recoverWithCode);
  wire('btn-recover-totp', recoverWithTotp);
  wire('btn-totp-begin', () => beginTotpEnrollment('register'));
  wire('btn-register-skip', finishRegistration);
  wire('btn-manage-totp', () => beginTotpEnrollment('login'));
  wire('btn-totp-confirm', confirmTotpEnrollment);
  wire('btn-totp-close', closeTotpEnrollment);
  refreshHint();
} else {
  status('当前浏览器不支持本页所需的 WebAuthn 接口，请使用较新的浏览器', true);
  setBusy(true);
}
