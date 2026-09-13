/* ============================================================
   密语 · 生产级密码工具
   ============================================================ */

/* ---------- 全局状态 ---------- */
const state = { crackAbort:false };

/* ---------- Toast ---------- */
function toast(msg, type='info', duration=2500) {
  const c = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => {
    el.classList.add('out');
    setTimeout(() => el.remove(), 200);
  }, duration);
}

/* ---------- 工具 ---------- */
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
   密钥派生
   ============================================================ */
async function deriveKey(masterPwd, salt, usages=['encrypt','decrypt']) {
  const km = await crypto.subtle.importKey('raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    km,
    {name:'AES-GCM', length:256},
    false,
    usages
  );
}

/* ============================================================
   AES-256-GCM
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
   AES-256-CBC
   ============================================================ */
async function aesCbcEncrypt(plain, key) {
  const iv = rand(16);
  const ct = await crypto.subtle.encrypt({name:'AES-CBC',iv}, key, utf8(plain));
  return {ct:new Uint8Array(ct), iv};
}
async function aesCbcDecrypt(ct, iv, key) {
  const pt = await crypto.subtle.decrypt({name:'AES-CBC',iv}, key, ct);
  return fromUtf8(pt);
}
async function deriveCbcKey(masterPwd, salt) {
  const km = await crypto.subtle.importKey('raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    km,
    {name:'AES-CBC', length:256},
    false,
    ['encrypt','decrypt']
  );
}

/* ============================================================
   XOR / Base64 / Hex / Caesar / Reverse
   ============================================================ */
function xorCipher(text, key) {
  const t = utf8(text), k = utf8(key||'x');
  const out = new Uint8Array(t.length);
  for (let i=0;i<t.length;i++) out[i] = t[i]^k[i%k.length];
  return out;
}
function caesarShift(text, shift) {
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 32 && code <= 126) return String.fromCharCode(((code-32+shift)%95+95)%95+32);
    return c;
  }).join('');
}
function reverseStr(s) { return s.split('').reverse().join(''); }

/* ============================================================
   Argon2id
   ============================================================ */
async function argon2Hash(password, salt) {
  const r = await argon2.hash({
    pass:password, salt,
    time:3, mem:65536, hashLen:32, parallelism:1,
    type:argon2.ArgonType.Argon2id
  });
  return r.hashHex;
}

/* ============================================================
   Token 封装
   ============================================================ */
function makeToken(payload) {
  const json = JSON.stringify(payload);
  return 'MIYU1:' + b64e(utf8(json));
}
function parseToken(token) {
  if (!token.startsWith('MIYU1:')) throw new Error('Token 格式错误');
  const json = fromUtf8(b64d(token.slice(6)));
  return JSON.parse(json);
}

/* ============================================================
   IndexedDB: 密码库 + 密钥库
   ============================================================ */
const DB_NAME = 'miyu-db', DB_VER = 2;
const STORE_VAULT = 'vault', STORE_KEYS = 'keys';

function openDB() {
  return new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (!db.objectStoreNames.contains(STORE_VAULT)) db.createObjectStore(STORE_VAULT, {keyPath:'id'});
      if (!db.objectStoreNames.contains(STORE_KEYS)) db.createObjectStore(STORE_KEYS, {keyPath:'id'});
    };
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function dbPut(store, obj) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(obj);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}
async function dbAll(store) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function dbDelete(store, id) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(id);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}
async function dbClear(store) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).clear();
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}

/* ============================================================
   UI
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  const $ = id => document.getElementById(id);

  /* ---------- Tabs ---------- */
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      $('tab-' + t.dataset.tab).classList.add('active');
      if (t.dataset.tab === 'keys') renderKeys();
      if (t.dataset.tab === 'vault') renderVault();
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
    toast('已生成随机主密钥', 'success');
  });

  /* ---------- 加密模式切换 ---------- */
  $('encryptMode').addEventListener('change', e => {
    const isSingle = e.target.value === 'single';
    $('singleModeField').style.display = isSingle ? 'block' : 'none';
    $('segmentedModeField').style.display = isSingle ? 'none' : 'block';
  });

  /* ---------- 重置 ---------- */
  $('resetBtn').addEventListener('click', () => {
    masterKey.value = '';
    $('plainText').value = '生产环境测试消息';
    $('cipherOutput').textContent = '等待加密...';
    $('decryptInput').value = '';
    $('decryptOutput').textContent = '等待解密...';
    updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
    toast('已重置', 'info');
  });

  /* ---------- 加密 ---------- */
  $('encryptBtn').addEventListener('click', async () => {
    const pwd = masterKey.value.trim();
    if (!pwd) return toast('请输入主密钥', 'error');
    const plain = $('plainText').value;
    if (!plain) return toast('请输入明文', 'error');
    const mode = $('encryptMode').value;
    const param = parseInt($('paramInput').value) || 3;

    const btn = $('encryptBtn');
    btn.disabled = true;

    try {
      let token;
      if (mode === 'single') {
        token = await encryptSingle(plain, pwd, $('encryptMethod').value, param);
      } else {
        token = await encryptSegmented(plain, pwd, $('segmentRules').value, param);
      }
      $('cipherOutput').textContent = token;
      const meta = parseToken(token);
      if (meta.m === 'aes-gcm' || meta.m === 'aes-cbc') {
        $('securityLabel').textContent = '真实安全 (WebCrypto ' + meta.m.toUpperCase() + ')';
        $('securityLabel').className = 'security-tag real';
      } else if (meta.m === 'argon2') {
        $('securityLabel').textContent = '真实安全 (Argon2id WASM)';
        $('securityLabel').className = 'security-tag real';
      } else if (meta.m === 'segmented') {
        $('securityLabel').textContent = '组合加密 (' + meta.segments.length + ' 段)';
        $('securityLabel').className = 'security-tag real';
      } else {
        $('securityLabel').textContent = '教学用，不安全';
        $('securityLabel').className = 'security-tag weak';
      }
      toast('加密成功', 'success');
    } catch (e) {
      $('cipherOutput').textContent = '加密失败: ' + e.message;
      toast('加密失败: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  /* ---------- 单一加密 ---------- */
  async function encryptSingle(plain, pwd, method, param) {
    if (method === 'aes-gcm') {
      const salt = rand(16);
      const key = await deriveKey(pwd, salt);
      const {ct, iv} = await aesGcmEncrypt(plain, key);
      return makeToken({m:'aes-gcm', s:toHex(salt), i:toHex(iv), c:b64e(ct)});
    }
    if (method === 'aes-cbc') {
      const salt = rand(16);
      const key = await deriveCbcKey(pwd, salt);
      const {ct, iv} = await aesCbcEncrypt(plain, key);
      return makeToken({m:'aes-cbc', s:toHex(salt), i:toHex(iv), c:b64e(ct)});
    }
    if (method === 'xor') {
      const salt = rand(16);
      const ct = xorCipher(plain, pwd + toHex(salt));
      return makeToken({m:'xor', s:toHex(salt), c:b64e(ct)});
    }
    if (method === 'base64') {
      return makeToken({m:'base64', c:b64e(utf8(plain))});
    }
    if (method === 'hex') {
      return makeToken({m:'hex', c:toHex(utf8(plain))});
    }
    if (method === 'caesar') {
      return makeToken({m:'caesar', p:param, c:caesarShift(plain, param)});
    }
    if (method === 'reverse') {
      return makeToken({m:'reverse', c:reverseStr(plain)});
    }
    if (method === 'argon2') {
      const salt = rand(16);
      const hash = await argon2Hash(plain, salt);
      return makeToken({m:'argon2', s:toHex(salt), h:hash});
    }
    throw new Error('未知方式');
  }

  /* ---------- 分段组合加密 ---------- */
  async function encryptSegmented(plain, pwd, rulesText, defaultParam) {
    const rules = rulesText.split('\n').map(l => l.trim()).filter(Boolean).map(line => {
      const m = line.match(/^(\d+)-(\d+):([\w-]+)(?::(\d+))?$/);
      if (!m) throw new Error('规则格式错误: ' + line);
      return {start:parseInt(m[1]), end:parseInt(m[2]), method:m[3], param: m[4] ? parseInt(m[4]) : defaultParam};
    });
    if (!rules.length) throw new Error('请填写至少一条规则');

    const bytes = utf8(plain);
    const total = bytes.length;
    const segments = [];
    const output = [];

    for (const rule of rules) {
      const s = Math.max(1, rule.start) - 1;
      const e = Math.min(total, rule.end);
      if (s >= e) continue;
      const slice = bytes.slice(s, e);
      const text = fromUtf8(slice);
      const enc = await encryptSegmentText(text, pwd, rule.method, rule.param);
      segments.push({method:rule.method, param:rule.param, data:enc, range:[s+1, e]});
      output.push(enc);
    }

    // 处理未覆盖部分（原样保留，标为 raw）
    const covered = new Set();
    rules.forEach(r => { for (let i=r.start;i<=r.end;i++) covered.add(i); });
    let rawParts = '';
    for (let i=1;i<=total;i++) {
      if (!covered.has(i)) rawParts += String.fromCharCode(bytes[i-1]);
    }

    return makeToken({
      m:'segmented',
      segments: segments.map(s => ({m:s.method, p:s.param, d:s.data, r:s.range})),
      raw: b64e(utf8(rawParts))
    });
  }

  async function encryptSegmentText(text, pwd, method, param) {
    if (method === 'aes-gcm') {
      const salt = rand(16);
      const key = await deriveKey(pwd, salt);
      const {ct, iv} = await aesGcmEncrypt(text, key);
      return {s:toHex(salt), i:toHex(iv), c:b64e(ct)};
    }
    if (method === 'aes-cbc') {
      const salt = rand(16);
      const key = await deriveCbcKey(pwd, salt);
      const {ct, iv} = await aesCbcEncrypt(text, key);
      return {s:toHex(salt), i:toHex(iv), c:b64e(ct)};
    }
    if (method === 'base64') return {c:b64e(utf8(text))};
    if (method === 'hex') return {c:toHex(utf8(text))};
    if (method === 'caesar') return {c:caesarShift(text, param)};
    if (method === 'reverse') return {c:reverseStr(text)};
    if (method === 'xor') {
      const salt = rand(16);
      return {s:toHex(salt), c:b64e(xorCipher(text, pwd + toHex(salt)))};
    }
    throw new Error('不支持的分段方式: ' + method);
  }

  /* ---------- 解密 ---------- */
  $('decryptBtn').addEventListener('click', async () => {
    const pwd = masterKey.value.trim();
    const token = $('decryptInput').value.trim();
    if (!token) return toast('请粘贴密文 Token', 'error');
    if (!pwd) return toast('请输入主密钥', 'error');

    try {
      const plain = await decryptToken(token, pwd);
      $('decryptOutput').textContent = plain;
      toast('解密成功', 'success');
    } catch (e) {
      $('decryptOutput').textContent = '解密失败: ' + e.message;
      toast('解密失败', 'error');
    }
  });

  async function decryptToken(token, pwd) {
    const meta = parseToken(token);
    if (meta.m === 'aes-gcm') {
      const key = await deriveKey(pwd, fromHex(meta.s));
      return aesGcmDecrypt(b64d(meta.c), fromHex(meta.i), key);
    }
    if (meta.m === 'aes-cbc') {
      const key = await deriveCbcKey(pwd, fromHex(meta.s));
      return aesCbcDecrypt(b64d(meta.c), fromHex(meta.i), key);
    }
    if (meta.m === 'xor') {
      const ct = b64d(meta.c);
      const k = utf8(pwd + meta.s);
      const out = new Uint8Array(ct.length);
      for (let i=0;i<ct.length;i++) out[i] = ct[i]^k[i%k.length];
      return fromUtf8(out);
    }
    if (meta.m === 'base64') return fromUtf8(b64d(meta.c));
    if (meta.m === 'hex') return fromUtf8(fromHex(meta.c));
    if (meta.m === 'caesar') return caesarShift(meta.c, -meta.p);
    if (meta.m === 'reverse') return reverseStr(meta.c);
    if (meta.m === 'argon2') {
      const h = await argon2Hash($('plainText').value, fromHex(meta.s));
      return h === meta.h ? '(哈希匹配，但 Argon2id 不可逆)' : '(哈希不匹配)';
    }
    if (meta.m === 'segmented') {
      const parts = [];
      for (const seg of meta.segments) {
        const dec = await decryptSegmentText(seg, pwd);
        parts.push(dec);
      }
      // 拼接 raw 部分（如果有）
      if (meta.raw) parts.push(fromUtf8(b64d(meta.raw)));
      return parts.join('');
    }
    throw new Error('未知方式');
  }

  async function decryptSegmentText(seg, pwd) {
    if (seg.m === 'aes-gcm') {
      const key = await deriveKey(pwd, fromHex(seg.d.s));
      return aesGcmDecrypt(b64d(seg.d.c), fromHex(seg.d.i), key);
    }
    if (seg.m === 'aes-cbc') {
      const key = await deriveCbcKey(pwd, fromHex(seg.d.s));
      return aesCbcDecrypt(b64d(seg.d.c), fromHex(seg.d.i), key);
    }
    if (seg.m === 'base64') return fromUtf8(b64d(seg.d.c));
    if (seg.m === 'hex') return fromUtf8(fromHex(seg.d.c));
    if (seg.m === 'caesar') return caesarShift(seg.d.c, -seg.p);
    if (seg.m === 'reverse') return reverseStr(seg.d.c);
    if (seg.m === 'xor') {
      const ct = b64d(seg.d.c);
      const k = utf8(pwd + seg.d.s);
      const out = new Uint8Array(ct.length);
      for (let i=0;i<ct.length;i++) out[i] = ct[i]^k[i%k.length];
      return fromUtf8(out);
    }
    throw new Error('不支持的分段: ' + seg.m);
  }

  /* ---------- 复制 ---------- */
  const copyBtn = (btnId, getter) => {
    $(btnId).addEventListener('click', () => {
      const text = getter();
      if (!text || text.startsWith('等待')) return toast('没有内容可复制', 'error');
      navigator.clipboard.writeText(text);
      const use = $(btnId).querySelector('use');
      use.setAttribute('href', '#i-check');
      toast('已复制', 'success');
      setTimeout(() => use.setAttribute('href', '#i-copy'), 1000);
    });
  };
  copyBtn('copyCipher', () => $('cipherOutput').textContent);

  $('useCipherAsInput').addEventListener('click', () => {
    const t = $('cipherOutput').textContent;
    if (!t || t.startsWith('等待')) return toast('没有密文', 'error');
    $('decryptInput').value = t;
    toast('已填入解密框', 'info');
  });

  /* ============================================================
     密钥管理
     ============================================================ */
  $('keyType').addEventListener('change', e => {
    $('subkeyField').style.display = e.target.value === 'subkey' ? 'block' : 'none';
    if (e.target.value === 'subkey') refreshSubkeyParent();
  });

  async function refreshSubkeyParent() {
    const keys = await dbAll(STORE_KEYS);
    const sel = $('subkeyParent');
    sel.innerHTML = keys.map(k => `<option value="${k.id}">${k.name} (${k.type})</option>`).join('');
    if (!keys.length) sel.innerHTML = '<option value="">请先生成主密钥</option>';
  }

  $('genKeyBtn').addEventListener('click', async () => {
    const type = $('keyType').value;
    const name = $('keyName').value.trim() || (type + '-' + Date.now());
    try {
      let entry;
      if (type === 'ecdh') {
        const kp = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'}, true, ['deriveKey','deriveBits']);
        const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
        const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
        entry = {id:crypto.randomUUID(), type:'ecdh', name, publicKey:toHex(pub), privateKey:b64e(priv), createdAt:Date.now()};
      } else if (type === 'ed25519') {
        try {
          const kp = await crypto.subtle.generateKey({name:'Ed25519'}, true, ['sign','verify']);
          const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
          const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
          entry = {id:crypto.randomUUID(), type:'ed25519', name, publicKey:toHex(pub), privateKey:b64e(priv), createdAt:Date.now()};
        } catch (e) {
          toast('当前浏览器不支持 Ed25519', 'error');
          return;
        }
      } else if (type === 'subkey') {
        const parentId = $('subkeyParent').value;
        if (!parentId) return toast('请先选择主密钥', 'error');
        const info = $('subkeyInfo').value.trim() || 'encryption';
        // 用 HKDF 从主密钥派生（此处以主密钥作为 IKM 演示）
        const parent = (await dbAll(STORE_KEYS)).find(k => k.id === parentId);
        if (!parent) return toast('主密钥不存在', 'error');
        const ikm = parent.privateKey ? b64d(parent.privateKey) : utf8(parent.name);
        const salt = rand(16);
        const km = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits(
          {name:'HKDF', hash:'SHA-256', salt, info:utf8(info)},
          km, 256
        );
        entry = {
          id:crypto.randomUUID(), type:'subkey', name,
          parentId: parent.id, info,
          key: toHex(new Uint8Array(bits)), salt: toHex(salt),
          createdAt: Date.now()
        };
      }
      await dbPut(STORE_KEYS, entry);
      $('keyName').value = '';
      await renderKeys();
      await refreshSubkeyParent();
      toast('密钥已生成', 'success');
    } catch (e) {
      toast('生成失败: ' + e.message, 'error');
    }
  });

  async function renderKeys() {
    const keys = await dbAll(STORE_KEYS);
    const list = $('keyList');
    if (!keys.length) {
      list.innerHTML = '<div class="empty-state">暂无密钥</div>';
      return;
    }
    list.innerHTML = keys.map(k => `
      <div class="vault-item" data-id="${k.id}">
        <div class="vault-item-header">
          <span class="vault-item-title">${escapeHtml(k.name)}</span>
          <div class="vault-item-actions">
            <button class="btn-icon" data-act="export" title="导出 JSON"><svg class="icon-sm"><use href="#i-download"/></svg></button>
            <button class="btn-icon" data-act="delete" title="删除"><svg class="icon-sm"><use href="#i-trash"/></svg></button>
          </div>
        </div>
        <div class="vault-item-row">类型: ${k.type}</div>
        ${k.publicKey ? `<div class="vault-item-row">公钥: ${k.publicKey.slice(0,48)}...</div>` : ''}
        ${k.key ? `<div class="vault-item-row">密钥: ${k.key.slice(0,48)}...</div>` : ''}
        ${k.info ? `<div class="vault-item-row">用途: ${escapeHtml(k.info)}</div>` : ''}
        <div class="vault-item-row">创建: ${new Date(k.createdAt).toLocaleString()}</div>
      </div>
    `).join('');
  }

  $('keyList').addEventListener('click', async ev => {
    const btn = ev.target.closest('button');
    if (!btn) return;
    const id = btn.closest('.vault-item').dataset.id;
    const act = btn.dataset.act;
    if (act === 'delete') {
      if (!confirm('确认删除此密钥？')) return;
      await dbDelete(STORE_KEYS, id);
      await renderKeys();
      await refreshSubkeyParent();
      toast('已删除', 'success');
    } else if (act === 'export') {
      const all = await dbAll(STORE_KEYS);
      const k = all.find(x => x.id === id);
      if (!k) return;
      const blob = new Blob([JSON.stringify(k, null, 2)], {type:'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = k.name + '.json'; a.click();
      URL.revokeObjectURL(url);
      toast('已导出', 'success');
    }
  });

  $('importKeyBtn').addEventListener('click', async () => {
    try {
      const obj = JSON.parse($('importKeyInput').value);
      if (!obj.id) obj.id = crypto.randomUUID();
      if (!obj.createdAt) obj.createdAt = Date.now();
      await dbPut(STORE_KEYS, obj);
      await renderKeys();
      await refreshSubkeyParent();
      $('importKeyInput').value = '';
      toast('导入成功', 'success');
    } catch (e) {
      toast('导入失败: ' + e.message, 'error');
    }
  });

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
    toast('已生成密码', 'success');
  });

  $('saveVaultBtn').addEventListener('click', async () => {
    const masterPwd = masterKey.value.trim();
    if (!masterPwd) return toast('请先在「加解密」中输入主密钥', 'error');
    const title = $('vaultTitle').value.trim();
    const username = $('vaultUsername').value.trim();
    const password = vaultPwd.value;
    const note = $('vaultNote').value.trim();
    if (!title || !password) return toast('标题和密码不能为空', 'error');

    try {
      const id = crypto.randomUUID();
      const salt = rand(16);
      const kek = await deriveKey(masterPwd, salt);
      const dek = rand(32);
      const dekKey = await crypto.subtle.importKey('raw', dek, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
      const {ct, iv} = await aesGcmEncrypt(password, dekKey);
      const dekIv = rand(12);
      const wrappedDek = new Uint8Array(await crypto.subtle.encrypt(
        {name:'AES-GCM', iv:dekIv}, kek, dek
      ));

      await dbPut(STORE_VAULT, {
        id, title, username, note,
        salt:toHex(salt), iv:toHex(iv), dekIv:toHex(dekIv),
        cipher: b64e(ct), wrappedDek: b64e(wrappedDek),
        createdAt: Date.now()
      });
      $('vaultTitle').value = '';
      $('vaultUsername').value = '';
      vaultPwd.value = '';
      $('vaultNote').value = '';
      updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel'));
      await renderVault();
      toast('已保存', 'success');
    } catch (e) {
      toast('保存失败: ' + e.message, 'error');
    }
  });

  async function renderVault(filter = '') {
    const all = await dbAll(STORE_VAULT);
    const filtered = all.filter(e => 
      !filter || 
      e.title.toLowerCase().includes(filter.toLowerCase()) ||
      (e.username||'').toLowerCase().includes(filter.toLowerCase())
    );
    const list = $('vaultList');
    if (!filtered.length) {
      list.innerHTML = '<div class="empty-state">密码库为空</div>';
      return;
    }
    list.innerHTML = filtered.map(e => `
      <div class="vault-item" data-id="${e.id}">
        <div class="vault-item-header">
          <span class="vault-item-title">${escapeHtml(e.title)}</span>
          <div class="vault-item-actions">
            <button class="btn-icon" data-act="decrypt" title="解密显示"><svg class="icon-sm"><use href="#i-unlock"/></svg></button>
            <button class="btn-icon" data-act="delete" title="删除"><svg class="icon-sm"><use href="#i-trash"/></svg></button>
          </div>
        </div>
        <div class="vault-item-row">用户名: ${escapeHtml(e.username||'-')}</div>
        <div class="vault-item-row">密码: <span class="vault-item-pwd" data-pwd="${e.id}">••••••••</span></div>
        <div class="vault-item-row">备注: ${escapeHtml(e.note||'-')}</div>
        <div class="vault-item-row">创建: ${new Date(e.createdAt).toLocaleString()}</div>
      </div>
    `).join('');
  }

  $('vaultList').addEventListener('click', async ev => {
    const btn = ev.target.closest('button');
    if (!btn) return;
    const id = btn.closest('.vault-item').dataset.id;
    const act = btn.dataset.act;
    if (act === 'delete') {
      if (!confirm('确认删除？')) return;
      await dbDelete(STORE_VAULT, id);
      await renderVault($('vaultSearch').value);
      toast('已删除', 'success');
    } else if (act === 'decrypt') {
      const masterPwd = masterKey.value.trim();
      if (!masterPwd) return toast('请先在「加解密」中输入主密钥', 'error');
      const all = await dbAll(STORE_VAULT);
      const entry = all.find(e => e.id === id);
      if (!entry) return;
      try {
        const kek = await deriveKey(masterPwd, fromHex(entry.salt));
        const dek = new Uint8Array(await crypto.subtle.decrypt(
          {name:'AES-GCM', iv: fromHex(entry.dekIv)}, kek, b64d(entry.wrappedDek)
        ));
        const dekKey = await crypto.subtle.importKey('raw', dek, {name:'AES-GCM'}, false, ['decrypt']);
        const plain = await aesGcmDecrypt(b64d(entry.cipher), fromHex(entry.iv), dekKey);
        const span = document.querySelector(`[data-pwd="${id}"]`);
        span.textContent = plain;
        span.style.color = '#16a34a';
        toast('解密成功', 'success');
      } catch (e) {
        toast('解密失败: ' + e.message, 'error');
      }
    }
  });

  $('vaultSearch').addEventListener('input', e => renderVault(e.target.value));

  $('clearVaultBtn').addEventListener('click', async () => {
    if (!confirm('确认清空所有密码？')) return;
    await dbClear(STORE_VAULT);
    await renderVault();
    toast('已清空', 'success');
  });

  /* ============================================================
     破解演示
     ============================================================ */
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
  function* numericGen() { for (let i=0;i<10000;i++) yield String(i).padStart(4,'0'); }
  function* lowercaseGen() {
    const chars = 'abcdefghijklmnopqrstuvwxyz';
    function* rec(prefix, depth) {
      if (depth === 0) { yield prefix; return; }
      for (const c of chars) yield* rec(prefix+c, depth-1);
    }
    for (let len=1;len<=4;len++) yield* rec('', len);
  }

  $('crackBtn').addEventListener('click', async () => {
    const target = $('crackTarget').value.trim();
    if (!target) return toast('请输入 Token', 'error');
    let meta;
    try {
      meta = parseToken(target);
    } catch (e) {
      return toast('Token 格式错误', 'error');
    }
    if (meta.m !== 'aes-gcm') {
      return toast('目前只支持 AES-GCM Token 破解演示', 'error');
    }

    state.crackAbort = false;
    $('crackBtn').disabled = true;
    $('stopCrackBtn').disabled = false;
    $('crackStatus').textContent = '破解中...';
    $('crackResult').textContent = '-';

    const start = performance.now();
    let count = 0;
    let found = null;

    const mode = $('crackMode').value;
    let gen;
    if (mode === 'dict') gen = dictGen();
    else if (mode === 'numeric') gen = numericGen();
    else gen = lowercaseGen();

    const ct = b64d(meta.c), iv = fromHex(meta.i), salt = fromHex(meta.s);

    for (const guess of gen) {
      if (state.crackAbort) break;
      count++;
      try {
        const key = await deriveKey(guess, salt);
        const pt = await aesGcmDecrypt(ct, iv, key);
        found = {password:guess, plain:pt};
        break;
      } catch (e) { /* 继续 */ }

      if (count % 20 === 0) {
        const elapsed = performance.now() - start;
        $('crackCount').textContent = count.toLocaleString();
        $('crackTime').textContent = elapsed.toFixed(0) + ' ms';
        $('crackSpeed').textContent = (count / (elapsed/1000)).toFixed(1) + ' /s';
        await new Promise(r => setTimeout(r, 0));
      }
    }

    const elapsed = performance.now() - start;
    $('crackCount').textContent = count.toLocaleString();
    $('crackTime').textContent = elapsed.toFixed(0) + ' ms';
    $('crackSpeed').textContent = (count / (elapsed/1000)).toFixed(1) + ' /s';
    $('crackStatus').textContent = state.crackAbort ? '已停止' : '完成';
    $('crackResult').textContent = found 
      ? `密码: ${found.password}\n明文: ${found.plain}` 
      : '未找到（PBKDF2 600k 迭代导致速度极慢，这是好事）';
    $('crackBtn').disabled = false;
    $('stopCrackBtn').disabled = true;
    if (found) toast('找到密码！', 'success');
    else toast('未找到', 'info');
  });

  $('stopCrackBtn').addEventListener('click', () => { state.crackAbort = true; });

  /* ---------- 通用 ---------- */
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  /* ---------- 初始化 ---------- */
  updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
  updateStrength(vaultPwd, $('vaultStrengthFill'), $('vaultStrengthLabel'));
  renderVault();
  renderKeys();
  refreshSubkeyParent();
});
