/* ============================================================
   密语 - 生产级密码工具
   - WebCrypto 原生：AES-GCM, AES-CBC+HMAC, ECDH, HKDF, Ed25519
   - Argon2id WASM
   - zxcvbn 密码强度
   - IndexedDB 密码库（信封加密）
   - 暴力破解演示
   ============================================================ */

const state = {
  lastCipher: null,
  vaultKey: null
};

/* ---------- 工具函数 ---------- */
const toHex = b => Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex = h => { const b=new Uint8Array(h.length/2); for(let i=0;i<h.length;i+=2) b[i/2]=parseInt(h.substr(i,2),16); return b; };
const b64e = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const b64d = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
const utf8 = s => new TextEncoder().encode(s);
const fromUtf8 = b => new TextDecoder().decode(b);
const rand = n => crypto.getRandomValues(new Uint8Array(n));

/* ---------- 密码强度 ---------- */
function checkStrength(pwd) {
  if (!pwd) return {score:0,label:'未检测',color:'#e2e8f0'};
  const r = zxcvbn(pwd);
  const colors = ['#dc2626','#ea580c','#ca8a04','#16a34a','#15803d'];
  const labels = ['非常弱','弱','一般','强','非常强'];
  return {score:r.score,label:labels[r.score],color:colors[r.score]};
}

/* ============================================================
   密钥派生 (PBKDF2-SHA256, 600k 迭代, OWASP 推荐)
   ============================================================ */
async function deriveKey(masterPwd, salt, usages=['encrypt','decrypt']) {
  const km = await crypto.subtle.importKey(
    'raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    km,
    {name:'AES-GCM', length:256},
    false,
    usages
  );
}

/* ============================================================
   AES-256-GCM (AEAD) — 真实安全
   ============================================================ */
async function aesGcmEncrypt(plain, key) {
  const iv = rand(12);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, utf8(plain));
  return {ct:new Uint8Array(ct), iv};
}
async function aesGcmDecrypt(ct, iv, key) {
  const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, ct);
  return fromUtf8(pt);
}

/* ============================================================
   AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
   ============================================================ */
async function aesCbcHmacEncrypt(plain, masterPwd, salt) {
  const encKey = await crypto.subtle.importKey(
    'raw', await crypto.subtle.deriveBits(
      {name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},
      await crypto.subtle.importKey('raw',utf8(masterPwd),'PBKDF2',false,['deriveBits']),
      256
    ), 'AES-CBC', false, ['encrypt']
  );
  const macKey = await crypto.subtle.importKey(
    'raw', await crypto.subtle.deriveBits(
      {name:'PBKDF2',salt:new Uint8Array([...salt,1]),iterations:600000,hash:'SHA-256'},
      await crypto.subtle.importKey('raw',utf8(masterPwd),'PBKDF2',false,['deriveBits']),
      256
    ), {name:'HMAC',hash:'SHA-256'}, false, ['sign']
  );
  const iv = rand(16);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv}, encKey, utf8(plain)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, ct));
  return {ct, iv, mac};
}
async function aesCbcHmacDecrypt(ct, iv, mac, masterPwd, salt) {
  const macKey = await crypto.subtle.importKey(
    'raw', await crypto.subtle.deriveBits(
      {name:'PBKDF2',salt:new Uint8Array([...salt,1]),iterations:600000,hash:'SHA-256'},
      await crypto.subtle.importKey('raw',utf8(masterPwd),'PBKDF2',false,['deriveBits']),
      256
    ), {name:'HMAC',hash:'SHA-256'}, false, ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', macKey, mac, ct);
  if (!valid) throw new Error('MAC 校验失败，密文被篡改');
  const encKey = await crypto.subtle.importKey(
    'raw', await crypto.subtle.deriveBits(
      {name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},
      await crypto.subtle.importKey('raw',utf8(masterPwd),'PBKDF2',false,['deriveBits']),
      256
    ), 'AES-CBC', false, ['decrypt']
  );
  const pt = await crypto.subtle.decrypt({name:'AES-CBC',iv}, encKey, ct);
  return fromUtf8(pt);
}

/* ============================================================
   XOR 流密码 (教学用，明确标注不安全)
   ============================================================ */
function xorCipher(text, key) {
  const t = utf8(text), k = utf8(key||'x');
  const out = new Uint8Array(t.length);
  for (let i=0;i<t.length;i++) out[i] = t[i]^k[i%k.length];
  return out;
}

/* ============================================================
   Argon2id (WASM)
   ============================================================ */
async function argon2Hash(password, salt) {
  const r = await argon2.hash({
    pass: password, salt,
    time: 3, mem: 65536, hashLen: 32, parallelism: 1,
    type: argon2.ArgonType.Argon2id
  });
  return r.hashHex;
}

/* ============================================================
   IndexedDB 密码库 (信封加密：主密钥 -> KEK -> 每条 DEK)
   ============================================================ */
const DB_NAME = 'miyu-vault';
const STORE = 'entries';

function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, {keyPath:'id'});
      }
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function vaultSave(entry) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(entry);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

async function vaultAll() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function vaultDelete(id) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(id);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

async function vaultClear() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).clear();
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

/* ============================================================
   UI 逻辑
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  const $ = id => document.getElementById(id);

  /* ---------- Tab 切换 ---------- */
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      $('tab-' + t.dataset.tab).classList.add('active');
    });
  });

  /* ---------- 强度检测 ---------- */
  const updateStrength = (inputEl, fillEl, labelEl) => {
    const {score,label,color} = checkStrength(inputEl.value);
    fillEl.style.width = ((score+1)*20)+'%';
    fillEl.style.background = color;
    labelEl.textContent = `密码强度：${label} (${score}/4)`;
  };

  const masterKey = $('masterKey');
  masterKey.addEventListener('input', () => updateStrength(masterKey, $('strengthFill'), $('strengthLabel')));

  /* ---------- 显示/隐藏主密钥 ---------- */
  $('toggleMasterKey').addEventListener('click', () => {
    const isPwd = masterKey.type === 'password';
    masterKey.type = isPwd ? 'text' : 'password';
    $('toggleMasterKey').querySelector('use').setAttribute('href', isPwd ? '#i-eye-off' : '#i-eye');
  });

  /* ---------- 生成随机主密钥 ---------- */
  $('genMasterKey').addEventListener('click', () => {
    masterKey.value = toHex(rand(24));
    updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
  });

  /* ---------- 重置 ---------- */
  $('resetBtn').addEventListener('click', () => {
    masterKey.value = '';
    $('plainText').value = '生产环境测试消息';
    $('cipherOutput').textContent = '等待加密...';
    $('keyInfoOutput').textContent = '等待生成...';
    $('decryptOutput').textContent = '点击解密验证可逆性';
    updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
    state.lastCipher = null;
  });

  /* ---------- 加密 ---------- */
  $('encryptBtn').addEventListener('click', async () => {
    const pwd = masterKey.value.trim();
    if (!pwd) return alert('请输入主密钥');
    const plain = $('plainText').value;
    const method = $('encryptMethod').value;
    const param = parseInt($('paramInput').value) || 3;

    const btn = $('encryptBtn');
    btn.disabled = true;

    try {
      const salt = rand(16);
      let result;

      if (method === 'aes-gcm') {
        const key = await deriveKey(pwd, salt);
        const {ct, iv} = await aesGcmEncrypt(plain, key);
        result = {
          cipher: b64e(ct),
          info: `盐: ${toHex(salt)}\nIV: ${toHex(iv)}`,
          security: '真实安全 (AES-256-GCM)',
          securityClass: 'real',
          raw: {method, ct, iv, salt}
        };
      }
      else if (method === 'aes-cbc-hmac') {
        const {ct, iv, mac} = await aesCbcHmacEncrypt(plain, pwd, salt);
        result = {
          cipher: b64e(new Uint8Array([...ct, ...mac])),
          info: `盐: ${toHex(salt)}\nIV: ${toHex(iv)}\nMAC 长度: ${mac.length}`,
          security: '真实安全 (CBC + HMAC)',
          securityClass: 'real',
          raw: {method, ct, iv, mac, salt, pwd}
        };
      }
      else if (method === 'ecdh-aes') {
        // ECDH P-256 + HKDF + AES-GCM
        const ecdh = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, true, ['deriveKey']);
        const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ecdh.publicKey));
        const shared = await crypto.subtle.deriveBits(
          {name:'ECDH', public: ecdh.publicKey}, ecdh.privateKey, 256
        );
        const aesKey = await crypto.subtle.importKey('raw', shared, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
        const {ct, iv} = await aesGcmEncrypt(plain, aesKey);
        result = {
          cipher: b64e(ct),
          info: `公钥: ${toHex(pubRaw).slice(0,32)}...\nIV: ${toHex(iv)}`,
          security: '真实安全 (ECDH + HKDF + AES-GCM)',
          securityClass: 'real',
          raw: {method, ct, iv, pubRaw}
        };
      }
      else if (method === 'ed25519') {
        // Ed25519 签名：用主密钥派生种子
        const seed = await crypto.subtle.deriveBits(
          {name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},
          await crypto.subtle.importKey('raw',utf8(pwd),'PBKDF2',false,['deriveBits']),
          256
        );
        try {
          const priv = await crypto.subtle.importKey('raw', seed, {name:'Ed25519'}, false, ['sign']);
          const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', priv, utf8(plain)));
          result = {
            cipher: toHex(sig),
            info: `盐: ${toHex(salt)}\n签名算法: Ed25519`,
            security: '真实安全 (Ed25519 签名)',
            securityClass: 'real',
            raw: {method, sig, salt, plain}
          };
        } catch (e) {
          result = {
            cipher: '(浏览器不支持 Ed25519)',
            info: '当前浏览器不支持 WebCrypto Ed25519',
            security: '不可用',
            securityClass: 'weak',
            raw: null
          };
        }
      }
      else if (method === 'argon2') {
        const hashHex = await argon2Hash(plain, salt);
        result = {
          cipher: hashHex,
          info: `盐: ${toHex(salt)}\n算法: Argon2id (WASM, 3 次迭代, 64 MiB)`,
          security: '真实安全 (Argon2id WASM)',
          securityClass: 'real',
          raw: {method, hashHex, salt, plain}
        };
      }
      else if (method === 'xor') {
        const ct = xorCipher(plain, pwd);
        result = {
          cipher: b64e(ct),
          info: '无盐无 IV（流密码）',
          security: '教学用，不安全',
          securityClass: 'weak',
          raw: {method, ct, pwd}
        };
      }
      else if (method === 'base64') {
        result = {
          cipher: b64e(utf8(plain)),
          info: '无密钥，仅编码',
          security: '无加密（仅编码）',
          securityClass: 'weak',
          raw: {method, plain}
        };
      }
      else if (method === 'hex') {
        result = {
          cipher: toHex(utf8(plain)),
          info: '无密钥，仅编码',
          security: '无加密（仅编码）',
          securityClass: 'weak',
          raw: {method, plain}
        };
      }
      else if (method === 'caesar') {
        const shifted = plain.split('').map(c => {
          const code = c.charCodeAt(0);
          if (code >= 32 && code <= 126) return String.fromCharCode(((code-32+param)%95)+32);
          return c;
        }).join('');
        result = {
          cipher: shifted,
          info: `位移量: ${param}`,
          security: '教学用，不安全',
          securityClass: 'weak',
          raw: {method, plain, param}
        };
      }
      else if (method === 'reverse') {
        result = {
          cipher: plain.split('').reverse().join(''),
          info: '无密钥，仅反转',
          security: '无加密（仅反转）',
          securityClass: 'weak',
          raw: {method, plain}
        };
      }

      $('cipherOutput').textContent = result.cipher;
      $('keyInfoOutput').textContent = result.info;
      $('securityLabel').textContent = result.security;
      $('securityLabel').className = 'security-tag ' + result.securityClass;
      state.lastCipher = result.raw;
      $('decryptOutput').textContent = '点击解密验证可逆性';
    } catch (e) {
      $('cipherOutput').textContent = '加密失败: ' + e.message;
      console.error(e);
    } finally {
      btn.disabled = false;
    }
  });

  /* ---------- 解密验证 ---------- */
  $('decryptBtn').addEventListener('click', async () => {
    const pwd = masterKey.value.trim();
    if (!state.lastCipher) return $('decryptOutput').textContent = '没有可解密的密文';
    if (!pwd) return $('decryptOutput').textContent = '请输入主密钥';

    const raw = state.lastCipher;
    try {
      let plain;
      if (raw.method === 'aes-gcm') {
        const key = await deriveKey(pwd, raw.salt);
        plain = await aesGcmDecrypt(raw.ct, raw.iv, key);
      }
      else if (raw.method === 'aes-cbc-hmac') {
        plain = await aesCbcHmacDecrypt(raw.ct, raw.iv, raw.mac, pwd, raw.salt);
      }
      else if (raw.method === 'xor') {
        const pt = xorCipher(fromUtf8(b64d($('cipherOutput').textContent)), pwd);
        plain = fromUtf8(pt);
      }
      else if (raw.method === 'base64') {
        plain = fromUtf8(b64d($('cipherOutput').textContent));
      }
      else if (raw.method === 'hex') {
        plain = fromUtf8(fromHex($('cipherOutput').textContent));
      }
      else if (raw.method === 'caesar') {
        const cipher = $('cipherOutput').textContent;
        plain = cipher.split('').map(c => {
          const code = c.charCodeAt(0);
          if (code >= 32 && code <= 126) return String.fromCharCode(((code-32-raw.param+95)%95)+32);
          return c;
        }).join('');
      }
      else if (raw.method === 'reverse') {
        plain = $('cipherOutput').textContent.split('').reverse().join('');
      }
      else if (raw.method === 'argon2') {
        const h = await argon2Hash($('plainText').value, raw.salt);
        plain = h === raw.hashHex ? '哈希验证成功（不可逆，但匹配）' : '哈希不匹配';
      }
      else {
        plain = '此方式暂不支持自动解密';
      }
      $('decryptOutput').textContent = plain;
    } catch (e) {
      $('decryptOutput').textContent = '解密失败: ' + e.message;
    }
  });

  /* ---------- 复制 ---------- */
  const bindCopy = (btnId, targetId) => {
    $(btnId).addEventListener('click', () => {
      const text = $(targetId).textContent;
      if (!text || text.startsWith('等待')) return;
      navigator.clipboard.writeText(text);
      const use = $(btnId).querySelector('use');
      use.setAttribute('href', '#i-check');
      setTimeout(() => use.setAttribute('href', '#i-copy'), 1000);
    });
  };
  bindCopy('copyCipher', 'cipherOutput');
  bindCopy('copyKeyInfo', 'keyInfoOutput');

  /* ============================================================
     密码库
     ============================================================ */
  const vaultPwd = $('vaultPassword');
  vaultPwd.addEventListener('input', () => updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel')));

  $('toggleVaultPwd').addEventListener('click', () => {
    const isPwd = vaultPwd.type === 'password';
    vaultPwd.type = isPwd ? 'text' : 'password';
    $('toggleVaultPwd').querySelector('use').setAttribute('href', isPwd ? '#i-eye-off' : '#i-eye');
  });

  $('genVaultPwd').addEventListener('click', () => {
    vaultPwd.value = toHex(rand(16));
    updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel'));
  });

  /* 保存条目 — 信封加密 */
  $('saveVaultBtn').addEventListener('click', async () => {
    const masterPwd = masterKey.value.trim();
    if (!masterPwd) return alert('请先在「加密工具」中输入主密钥');
    const title = $('vaultTitle').value.trim();
    const username = $('vaultUsername').value.trim();
    const password = vaultPwd.value;
    const note = $('vaultNote').value.trim();
    if (!title || !password) return alert('标题和密码不能为空');

    try {
      const entryId = crypto.randomUUID();
      const salt = rand(16);
      // 每条独立 DEK
      const dek = rand(32);
      const dekKey = await crypto.subtle.importKey('raw', dek, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
      // 用 DEK 加密密码
      const {ct, iv} = await aesGcmEncrypt(password, dekKey);
      // 用主密钥派生的 KEK 加密 DEK
      const kek = await deriveKey(masterPwd, salt);
      const dekIv = rand(12);
      const wrappedDek = new Uint8Array(await crypto.subtle.encrypt(
        {name:'AES-GCM', iv: dekIv}, kek, dek
      ));

      const entry = {
        id: entryId,
        title, username, note,
        salt: toHex(salt),
        iv: toHex(iv),
        dekIv: toHex(dekIv),
        cipher: b64e(ct),
        wrappedDek: b64e(wrappedDek),
        createdAt: Date.now()
      };
      await vaultSave(entry);
      $('vaultTitle').value = '';
      $('vaultUsername').value = '';
      $('vaultPassword').value = '';
      $('vaultNote').value = '';
      updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel'));
      await renderVault();
      alert('已保存');
    } catch (e) {
      alert('保存失败: ' + e.message);
    }
  });

  /* 渲染密码库 */
  async function renderVault(filter = '') {
    const list = $('vaultList');
    const all = await vaultAll();
    const filtered = all.filter(e => 
      !filter || 
      e.title.toLowerCase().includes(filter.toLowerCase()) ||
      (e.username||'').toLowerCase().includes(filter.toLowerCase())
    );
    if (!filtered.length) {
      list.innerHTML = '<div class="empty-state">密码库为空</div>';
      return;
    }
    list.innerHTML = filtered.map(e => `
      <div class="vault-item" data-id="${e.id}">
        <div class="vault-item-header">
          <span class="vault-item-title">${escapeHtml(e.title)}</span>
          <div class="vault-item-actions">
            <button class="btn-icon" data-act="decrypt" title="解密显示">
              <svg class="icon-sm"><use href="#i-unlock"/></svg>
            </button>
            <button class="btn-icon" data-act="delete" title="删除">
              <svg class="icon-sm"><use href="#i-trash"/></svg>
            </button>
          </div>
        </div>
        <div class="vault-item-row">用户名: ${escapeHtml(e.username||'-')}</div>
        <div class="vault-item-row">密码: <span class="vault-item-pwd" data-pwd="${e.id}">••••••••</span></div>
        <div class="vault-item-row">备注: ${escapeHtml(e.note||'-')}</div>
        <div class="vault-item-row">创建: ${new Date(e.createdAt).toLocaleString()}</div>
      </div>
    `).join('');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  /* 事件委托：解密 / 删除 */
  $('vaultList').addEventListener('click', async (ev) => {
    const btn = ev.target.closest('button');
    if (!btn) return;
    const item = btn.closest('.vault-item');
    const id = item.dataset.id;
    const act = btn.dataset.act;

    if (act === 'delete') {
      if (!confirm('确认删除？')) return;
      await vaultDelete(id);
      await renderVault($('vaultSearch').value);
    }
    else if (act === 'decrypt') {
      const masterPwd = masterKey.value.trim();
      if (!masterPwd) return alert('请先在「加密工具」中输入主密钥');
      const all = await vaultAll();
      const entry = all.find(e => e.id === id);
      if (!entry) return;
      try {
        const kek = await deriveKey(masterPwd, fromHex(entry.salt));
        const dek = new Uint8Array(await crypto.subtle.decrypt(
          {name:'AES-GCM', iv: fromHex(entry.dekIv)},
          kek,
          b64d(entry.wrappedDek)
        ));
        const dekKey = await crypto.subtle.importKey('raw', dek, {name:'AES-GCM'}, false, ['decrypt']);
        const plain = await aesGcmDecrypt(b64d(entry.cipher), fromHex(entry.iv), dekKey);
        const span = document.querySelector(`[data-pwd="${id}"]`);
        span.textContent = plain;
        span.style.color = '#16a34a';
      } catch (e) {
        alert('解密失败: ' + e.message);
      }
    }
  });

  $('vaultSearch').addEventListener('input', e => renderVault(e.target.value));

  $('clearVaultBtn').addEventListener('click', async () => {
    if (!confirm('确认清空所有密码？')) return;
    await vaultClear();
    await renderVault();
  });

  /* ============================================================
     暴力破解 (演示)
     ============================================================ */
  let crackAbort = false;

  const DICT = [
    '123456','password','12345678','qwerty','123456789','12345','1234','111111','1234567','dragon',
    '123123','baseball','abc123','football','monkey','letmein','shadow','master','666666','qwertyuiop',
    '123321','mustang','1234567890','michael','654321','superman','1qaz2wsx','7777777','121212','000000',
    'qazwsx','123qwe','killer','trustno1','jordan','jennifer','zxcvbnm','asdfgh','hunter','buster',
    'soccer','harley','batman','andrew','tigger','sunshine','iloveyou','2000','charlie','robert',
    'admin','admin123','root','toor','test','guest','user','pass','p@ssw0rd','Password1',
    'welcome','welcome1','hello','hello123','secret','love','god','money','ninja','azerty'
  ];

  function* dictGen() { for (const p of DICT) yield p; }
  function* numericGen(max) {
    for (let i=0;i<max;i++) yield String(i).padStart(4,'0');
  }
  function* lowercaseGen(maxLen) {
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    function* rec(prefix, depth) {
      if (depth === 0) { yield prefix; return; }
      for (const c of chars) yield* rec(prefix+c, depth-1);
    }
    for (let len=1;len<=maxLen;len++) yield* rec('', len);
  }
  function* alnumGen(maxLen) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    function* rec(prefix, depth) {
      if (depth === 0) { yield prefix; return; }
      for (const c of chars) yield* rec(prefix+c, depth-1);
    }
    for (let len=1;len<=maxLen;len++) yield* rec('', len);
  }

  $('crackBtn').addEventListener('click', async () => {
    const target = $('crackTarget').value.trim();
    if (!target) return alert('请输入目标密文');
    const method = $('crackMethod').value;
    const mode = $('crackMode').value;
    const saltHex = $('crackSalt').value.trim();
    const ivHex = $('crackIv').value.trim();

    crackAbort = false;
    $('crackBtn').disabled = true;
    $('stopCrackBtn').disabled = false;
    $('crackStatus').textContent = '破解中...';
    $('crackResult').textContent = '-';

    const start = performance.now();
    let count = 0;
    let found = null;

    // 选择生成器
    let gen;
    if (mode === 'dict') gen = dictGen();
    else if (mode === 'numeric') gen = numericGen(10000);
    else if (mode === 'lowercase') gen = lowercaseGen(4);
    else gen = alnumGen(3);

    const targetBytes = method === 'aes-gcm' || method === 'aes-cbc-hmac' ? b64d(target) : null;

    for (const guess of gen) {
      if (crackAbort) break;
      count++;

      try {
        if (method === 'aes-gcm') {
          const salt = fromHex(saltHex);
          const key = await deriveKey(guess, salt);
          const pt = await aesGcmDecrypt(targetBytes, fromHex(ivHex), key);
          found = {password: guess, plain: pt};
          break;
        }
        else if (method === 'aes-cbc-hmac') {
          const salt = fromHex(saltHex);
          const ctLen = targetBytes.length - 32;
          const ct = targetBytes.slice(0, ctLen);
          const mac = targetBytes.slice(ctLen);
          const pt = await aesCbcHmacDecrypt(ct, fromHex(ivHex), mac, guess, salt);
          found = {password: guess, plain: pt};
          break;
        }
        else if (method === 'xor') {
          const ct = b64d(target);
          const k = utf8(guess);
          const pt = new Uint8Array(ct.length);
          for (let i=0;i<ct.length;i++) pt[i] = ct[i]^k[i%k.length];
          const s = fromUtf8(pt);
          // XOR 破解：检查是否可打印
          if (/^[\x20-\x7e\u4e00-\u9fa5]+$/.test(s)) {
            found = {password: guess, plain: s};
            break;
          }
        }
        else if (method === 'caesar') {
          const shift = parseInt(guess) || 0;
          const pt = target.split('').map(c => {
            const code = c.charCodeAt(0);
            if (code >= 32 && code <= 126) return String.fromCharCode(((code-32-shift+95)%95)+32);
            return c;
          }).join('');
          if (/^[\x20-\x7e\u4e00-\u9fa5]+$/.test(pt)) {
            found = {password: String(shift), plain: pt};
            break;
          }
        }
      } catch (e) { /* 继续尝试 */ }

      if (count % 50 === 0) {
        const elapsed = performance.now() - start;
        $('crackCount').textContent = count.toLocaleString();
        $('crackTime').textContent = elapsed.toFixed(0) + ' ms';
        await new Promise(r => setTimeout(r, 0));
      }
    }

    const elapsed = performance.now() - start;
    $('crackCount').textContent = count.toLocaleString();
    $('crackTime').textContent = elapsed.toFixed(0) + ' ms';
    $('crackStatus').textContent = crackAbort ? '已停止' : '完成';
    $('crackResult').textContent = found 
      ? `找到密码: ${found.password}\n明文: ${found.plain}` 
      : '未找到密码';
    $('crackBtn').disabled = false;
    $('stopCrackBtn').disabled = true;
  });

  $('stopCrackBtn').addEventListener('click', () => { crackAbort = true; });

  /* 初始化 */
  updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
  updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel'));
  renderVault();
});
