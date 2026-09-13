/* ============================================================
   密语 · 生产级密码工具
   ============================================================ */

const state = { crackAbort:false, currentKeyForModal:null };

/* ---------- Toast ---------- */
function toast(msg, type='info', duration=2500) {
  const c = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 200); }, duration);
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
   派生密钥
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
async function deriveAesCtrKey(masterPwd, salt) {
  const km = await crypto.subtle.importKey('raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    km,
    {name:'AES-CTR', length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function deriveAesCbcKey(masterPwd, salt) {
  const km = await crypto.subtle.importKey('raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    km,
    {name:'AES-CBC', length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function deriveHmacKey(masterPwd, salt) {
  const km = await crypto.subtle.importKey('raw', utf8(masterPwd), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt:new Uint8Array([...salt,1]), iterations:600000, hash:'SHA-256'},
    km,
    {name:'HMAC', hash:'SHA-256', length:256},
    false,
    ['sign','verify']
  );
}

/* ============================================================
   现代加密
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

async function aesCtrHmacEncrypt(plain, pwd, salt) {
  const ctrKey = await deriveAesCtrKey(pwd, salt);
  const macKey = await deriveHmacKey(pwd, salt);
  const iv = rand(16);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-CTR', counter:iv, length:64}, ctrKey, utf8(plain)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, ct));
  return {ct, iv, mac};
}
async function aesCtrHmacDecrypt(ct, iv, mac, pwd, salt) {
  const macKey = await deriveHmacKey(pwd, salt);
  const valid = await crypto.subtle.verify('HMAC', macKey, mac, ct);
  if (!valid) throw new Error('MAC 校验失败');
  const ctrKey = await deriveAesCtrKey(pwd, salt);
  const pt = await crypto.subtle.decrypt({name:'AES-CTR', counter:iv, length:64}, ctrKey, ct);
  return fromUtf8(pt);
}

async function aesCbcHmacEncrypt(plain, pwd, salt) {
  const cbcKey = await deriveAesCbcKey(pwd, salt);
  const macKey = await deriveHmacKey(pwd, salt);
  const iv = rand(16);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC', iv}, cbcKey, utf8(plain)));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, ct));
  return {ct, iv, mac};
}
async function aesCbcHmacDecrypt(ct, iv, mac, pwd, salt) {
  const macKey = await deriveHmacKey(pwd, salt);
  const valid = await crypto.subtle.verify('HMAC', macKey, mac, ct);
  if (!valid) throw new Error('MAC 校验失败');
  const cbcKey = await deriveAesCbcKey(pwd, salt);
  const pt = await crypto.subtle.decrypt({name:'AES-CBC', iv}, cbcKey, ct);
  return fromUtf8(pt);
}

/* ============================================================
   古典密码
   ============================================================ */
function caesarShift(text, shift) {
  shift = ((shift % 95) + 95) % 95;
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 32 && code <= 126) return String.fromCharCode(((code-32+shift)%95)+32);
    return c;
  }).join('');
}

function vigenere(text, key, encode=true) {
  const k = key.toUpperCase().replace(/[^A-Z]/g,'') || 'A';
  let ki = 0;
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      const shift = k.charCodeAt(ki % k.length) - 65;
      ki++;
      return String.fromCharCode(((code-65 + (encode?shift:-shift) + 26) % 26) + 65);
    }
    if (code >= 97 && code <= 122) {
      const shift = k.charCodeAt(ki % k.length) - 65;
      ki++;
      return String.fromCharCode(((code-97 + (encode?shift:-shift) + 26) % 26) + 97);
    }
    return c;
  }).join('');
}

function atbash(text) {
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code - 65));
    if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code - 97));
    return c;
  }).join('');
}

function rot13(text) { return caesarAlpha(text, 13); }
function rot47(text) {
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 33 && code <= 126) return String.fromCharCode(33 + ((code - 33 + 47) % 94));
    return c;
  }).join('');
}
function caesarAlpha(text, n) {
  return text.split('').map(c => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) return String.fromCharCode(((code-65+n)%26)+65);
    if (code >= 97 && code <= 122) return String.fromCharCode(((code-97+n)%26)+97);
    return c;
  }).join('');
}

function railFence(text, rails, encode=true) {
  if (rails < 2) return text;
  const len = text.length;
  const pattern = [];
  let r = 0, dir = 1;
  for (let i=0;i<len;i++) {
    pattern.push(r);
    r += dir;
    if (r === 0 || r === rails-1) dir = -dir;
  }
  if (encode) {
    const rows = Array.from({length:rails}, () => []);
    for (let i=0;i<len;i++) rows[pattern[i]].push(text[i]);
    return rows.map(row => row.join('')).join('');
  } else {
    const counts = new Array(rails).fill(0);
    for (const p of pattern) counts[p]++;
    const rows = [];
    let idx = 0;
    for (let i=0;i<rails;i++) { rows.push(text.slice(idx, idx+counts[i]).split('')); idx += counts[i]; }
    const result = [];
    const pointers = new Array(rails).fill(0);
    for (let i=0;i<len;i++) {
      const row = pattern[i];
      result.push(rows[row][pointers[row]++]);
    }
    return result.join('');
  }
}

const MORSE_MAP = {
  'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---',
  'K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-',
  'U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..',
  '0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.',
  '.':'.-.-.-',',':'--..--','?':'..--..','/':'-..-.',' ':'/'
};
const MORSE_REV = Object.fromEntries(Object.entries(MORSE_MAP).map(([k,v]) => [v,k]));

function morseEncode(text) {
  return text.toUpperCase().split('').map(c => MORSE_MAP[c] || '').filter(Boolean).join(' ');
}
function morseDecode(text) {
  return text.split(' ').map(code => MORSE_REV[code] || '').join('');
}

const BACON_MAP = {
  'A':'AAAAA','B':'AAAAB','C':'AAABA','D':'AAABB','E':'AABAA','F':'AABAB','G':'AABBA','H':'AABBB',
  'I':'ABAAA','J':'ABAAB','K':'ABABA','L':'ABABB','M':'ABBAA','N':'ABBAB','O':'ABBBA','P':'ABBBB',
  'Q':'BAAAA','R':'BAAAB','S':'BAABA','T':'BAABB','U':'BABAA','V':'BABAB','W':'BABBA','X':'BABBB',
  'Y':'BBAAA','Z':'BBAAB',' ':'BBBBB'
};
const BACON_REV = Object.fromEntries(Object.entries(BACON_MAP).map(([k,v]) => [v,k]));

function baconEncode(text) {
  return text.toUpperCase().split('').map(c => BACON_MAP[c] || '').filter(Boolean).join('');
}
function baconDecode(text) {
  const clean = text.replace(/[^ABab]/g,'').toUpperCase();
  let result = '';
  for (let i=0;i<clean.length;i+=5) {
    const chunk = clean.slice(i, i+5);
    result += BACON_REV[chunk] || '';
  }
  return result;
}

/* ============================================================
   编码格式
   ============================================================ */
function hexEncode(s) { return toHex(utf8(s)); }
function hexDecode(h) { return fromUtf8(fromHex(h)); }
function binaryEncode(s) { return Array.from(utf8(s)).map(b => b.toString(2).padStart(8,'0')).join(' '); }
function binaryDecode(s) {
  return fromUtf8(new Uint8Array(s.split(/\s+/).filter(Boolean).map(b => parseInt(b,2))));
}
function octalEncode(s) { return Array.from(utf8(s)).map(b => b.toString(8).padStart(3,'0')).join(' '); }
function octalDecode(s) {
  return fromUtf8(new Uint8Array(s.split(/\s+/).filter(Boolean).map(b => parseInt(b,8))));
}
function urlEncode(s) { return encodeURIComponent(s); }
function urlDecode(s) { return decodeURIComponent(s); }
function unicodeEncode(s) {
  return s.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0')).join('');
}
function unicodeDecode(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h,16)));
}

/* ============================================================
   XOR / RC4
   ============================================================ */
function xorCipher(text, key) {
  const t = utf8(text), k = utf8(key||'x');
  const out = new Uint8Array(t.length);
  for (let i=0;i<t.length;i++) out[i] = t[i]^k[i%k.length];
  return out;
}
function rc4(text, key) {
  const S = Array.from({length:256}, (_,i) => i);
  const k = utf8(key);
  let j = 0;
  for (let i=0;i<256;i++) {
    j = (j + S[i] + k[i%k.length]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const data = utf8(text);
  const out = new Uint8Array(data.length);
  let i = 0; j = 0;
  for (let n=0;n<data.length;n++) {
    i = (i+1) % 256;
    j = (j + S[i]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
    const K = S[(S[i]+S[j]) % 256];
    out[n] = data[n] ^ K;
  }
  return out;
}
function rc4Bytes(data, key) {
  const S = Array.from({length:256}, (_,i) => i);
  const k = utf8(key);
  let j = 0;
  for (let i=0;i<256;i++) {
    j = (j + S[i] + k[i%k.length]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
  }
  const out = new Uint8Array(data.length);
  let i = 0; j = 0;
  for (let n=0;n<data.length;n++) {
    i = (i+1) % 256;
    j = (j + S[i]) % 256;
    [S[i], S[j]] = [S[j], S[i]];
    const K = S[(S[i]+S[j]) % 256];
    out[n] = data[n] ^ K;
  }
  return out;
}

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
   Token
   ============================================================ */
function makeToken(payload) {
  return 'MIYU1:' + b64e(utf8(JSON.stringify(payload)));
}
function parseToken(token) {
  if (!token.startsWith('MIYU1:')) throw new Error('Token 格式错误');
  return JSON.parse(fromUtf8(b64d(token.slice(6))));
}

/* ============================================================
   IndexedDB
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

  $('toggleMasterKey').addEventListener('click', () => {
    const isPwd = masterKey.type === 'password';
    masterKey.type = isPwd ? 'text' : 'password';
    $('toggleMasterKey').querySelector('use').setAttribute('href', isPwd ? '#i-eye-off' : '#i-eye');
  });

  $('genMasterKey').addEventListener('click', () => {
    masterKey.value = toHex(rand(24));
    updateStrength(masterKey, $('strengthFill'), $('strengthLabel'));
    toast('已生成随机主密钥', 'success');
  });

  $('encryptMode').addEventListener('change', e => {
    const isSingle = e.target.value === 'single';
    $('singleModeField').style.display = isSingle ? 'block' : 'none';
    $('segmentedModeField').style.display = isSingle ? 'none' : 'block';
  });

  $('resetBtn').addEventListener('click', () => {
    masterKey.value = '';
    $('plainText').value = '生产环境测试消息';
    $('cipherOutput').textContent = '等待加密...';
    $('algorithmInfo').textContent = '-';
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
    const param = $('paramInput').value;
    const btn = $('encryptBtn');
    btn.disabled = true;

    try {
      let token, info;
      if (mode === 'single') {
        const result = await encryptSingle(plain, pwd, $('encryptMethod').value, param);
        token = result.token; info = result.info;
      } else {
        token = await encryptSegmented(plain, pwd, $('segmentRules').value, param);
        info = '分段组合加密';
      }
      $('cipherOutput').textContent = token;
      const meta = parseToken(token);
      const securityMap = {
        'aes-gcm':'真实安全 (AES-256-GCM)', 'aes-ctr-hmac':'真实安全 (AES-CTR + HMAC)',
        'aes-cbc-hmac':'真实安全 (AES-CBC + HMAC)', 'chacha20':'真实安全 (ChaCha20-Poly1305)',
        'argon2':'真实安全 (Argon2id 哈希)'
      };
      if (securityMap[meta.m]) {
        $('securityLabel').textContent = securityMap[meta.m];
        $('securityLabel').className = 'security-tag real';
      } else if (meta.m === 'segmented') {
        $('securityLabel').textContent = '组合加密 (' + meta.segments.length + ' 段)';
        $('securityLabel').className = 'security-tag real';
      } else {
        $('securityLabel').textContent = '教学用，不安全';
        $('securityLabel').className = 'security-tag weak';
      }
      $('algorithmInfo').textContent = info;
      toast('加密成功', 'success');
    } catch (e) {
      $('cipherOutput').textContent = '加密失败: ' + e.message;
      toast('加密失败: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  async function encryptSingle(plain, pwd, method, param) {
    // 现代
    if (method === 'aes-gcm') {
      const salt = rand(16);
      const key = await deriveKey(pwd, salt);
      const {ct, iv} = await aesGcmEncrypt(plain, key);
      return {token: makeToken({m:'aes-gcm', s:toHex(salt), i:toHex(iv), c:b64e(ct)}), info:'AES-256-GCM，PBKDF2 600k'};
    }
    if (method === 'aes-ctr-hmac') {
      const salt = rand(16);
      const {ct, iv, mac} = await aesCtrHmacEncrypt(plain, pwd, salt);
      return {token: makeToken({m:'aes-ctr-hmac', s:toHex(salt), i:toHex(iv), c:b64e(ct), mac:toHex(mac)}), info:'AES-256-CTR + HMAC-SHA256'};
    }
    if (method === 'aes-cbc-hmac') {
      const salt = rand(16);
      const {ct, iv, mac} = await aesCbcHmacEncrypt(plain, pwd, salt);
      return {token: makeToken({m:'aes-cbc-hmac', s:toHex(salt), i:toHex(iv), c:b64e(ct), mac:toHex(mac)}), info:'AES-256-CBC + HMAC-SHA256'};
    }
    if (method === 'chacha20') {
      // WebCrypto 对 ChaCha20-Poly1305 支持不统一，降级为 AES-GCM
      toast('当前浏览器 ChaCha20 支持不完整，使用 AES-GCM 替代', 'info');
      const salt = rand(16);
      const key = await deriveKey(pwd, salt);
      const {ct, iv} = await aesGcmEncrypt(plain, key);
      return {token: makeToken({m:'aes-gcm', s:toHex(salt), i:toHex(iv), c:b64e(ct)}), info:'降级为 AES-256-GCM'};
    }
    // 古典
    if (method === 'caesar') {
      const n = parseInt(param) || 3;
      return {token: makeToken({m:'caesar', p:n, c:caesarShift(plain, n)}), info:`凯撒位移 ${n}`};
    }
    if (method === 'vigenere') {
      const key = param || 'KEY';
      return {token: makeToken({m:'vigenere', k:key, c:vigenere(plain, key, true)}), info:`维吉尼亚，密钥 ${key}`};
    }
    if (method === 'atbash') {
      return {token: makeToken({m:'atbash', c:atbash(plain)}), info:'Atbash 字母反转'};
    }
    if (method === 'rot13') {
      return {token: makeToken({m:'rot13', c:rot13(plain)}), info:'ROT13'};
    }
    if (method === 'rot47') {
      return {token: makeToken({m:'rot47', c:rot47(plain)}), info:'ROT47'};
    }
    if (method === 'railfence') {
      const n = parseInt(param) || 3;
      return {token: makeToken({m:'railfence', p:n, c:railFence(plain, n, true)}), info:`栅栏密码 ${n} 栏`};
    }
    if (method === 'morse') {
      return {token: makeToken({m:'morse', c:morseEncode(plain)}), info:'摩斯电码'};
    }
    if (method === 'bacon') {
      return {token: makeToken({m:'bacon', c:baconEncode(plain)}), info:'培根密码'};
    }
    // 编码
    if (method === 'base64') return {token: makeToken({m:'base64', c:b64e(utf8(plain))}), info:'Base64 编码'};
    if (method === 'hex') return {token: makeToken({m:'hex', c:hexEncode(plain)}), info:'Hex 编码'};
    if (method === 'binary') return {token: makeToken({m:'binary', c:binaryEncode(plain)}), info:'二进制编码'};
    if (method === 'octal') return {token: makeToken({m:'octal', c:octalEncode(plain)}), info:'八进制编码'};
    if (method === 'url') return {token: makeToken({m:'url', c:urlEncode(plain)}), info:'URL 编码'};
    if (method === 'unicode') return {token: makeToken({m:'unicode', c:unicodeEncode(plain)}), info:'Unicode 转义'};
    if (method === 'reverse') return {token: makeToken({m:'reverse', c:plain.split('').reverse().join('')}), info:'字符串反转'};
    // 其他
    if (method === 'xor') {
      const salt = rand(16);
      return {token: makeToken({m:'xor', s:toHex(salt), c:b64e(xorCipher(plain, pwd + toHex(salt)))}), info:'XOR 流密码（教学）'};
    }
    if (method === 'rc4') {
      const salt = rand(16);
      return {token: makeToken({m:'rc4', s:toHex(salt), c:b64e(rc4(plain, pwd + toHex(salt)))}), info:'RC4（教学，不安全）'};
    }
    if (method === 'argon2') {
      const salt = rand(16);
      const hash = await argon2Hash(plain, salt);
      return {token: makeToken({m:'argon2', s:toHex(salt), h:hash}), info:'Argon2id 哈希（不可逆）'};
    }
    throw new Error('未知方式');
  }

  async function encryptSegmented(plain, pwd, rulesText, defaultParam) {
    const rules = rulesText.split('\n').map(l => l.trim()).filter(Boolean).map(line => {
      const m = line.match(/^(\d+)-(\d+):([\w-]+)(?::(.+))?$/);
      if (!m) throw new Error('规则格式错误: ' + line);
      return {start:parseInt(m[1]), end:parseInt(m[2]), method:m[3], param: m[4] || defaultParam};
    });
    if (!rules.length) throw new Error('请填写至少一条规则');
    const bytes = utf8(plain);
    const total = bytes.length;
    const segments = [];
    const covered = new Set();
    for (const rule of rules) {
      const s = Math.max(1, rule.start) - 1;
      const e = Math.min(total, rule.end);
      if (s >= e) continue;
      const text = fromUtf8(bytes.slice(s, e));
      const enc = await encryptSegmentText(text, pwd, rule.method, rule.param);
      segments.push({m:rule.method, p:rule.param, d:enc, r:[s+1, e]});
      for (let i=rule.start;i<=rule.end;i++) covered.add(i);
    }
    let rawParts = '';
    for (let i=1;i<=total;i++) if (!covered.has(i)) rawParts += String.fromCharCode(bytes[i-1]);
    return makeToken({
      m:'segmented',
      segments,
      raw: b64e(utf8(rawParts))
    });
  }

  async function encryptSegmentText(text, pwd, method, param) {
    const r = await encryptSingle(text, pwd, method, param);
    return r.token.replace('MIYU1:','');
  }

  /* ---------- 解密（独立区域） ---------- */
  $('toggleDecryptKey').addEventListener('click', () => {
    const el = $('decryptKey');
    const isPwd = el.type === 'password';
    el.type = isPwd ? 'text' : 'password';
    $('toggleDecryptKey').querySelector('use').setAttribute('href', isPwd ? '#i-eye-off' : '#i-eye');
  });

  $('decryptMethod').addEventListener('change', e => {
    $('decryptParamField').style.display = (e.target.value === 'auto') ? 'none' : 'block';
  });

  $('clearDecryptBtn').addEventListener('click', () => {
    $('decryptToken').value = '';
    $('decryptKey').value = '';
    $('decryptOutput').textContent = '等待解密...';
    $('tokenMeta').textContent = '-';
    toast('已清空', 'info');
  });

  $('useCipherAsInput').addEventListener('click', () => {
    const t = $('cipherOutput').textContent;
    if (!t || t.startsWith('等待')) return toast('没有密文', 'error');
    $('decryptToken').value = t;
    // 自动切换到解密 tab
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    document.querySelector('[data-tab="decrypt"]').classList.add('active');
    $('tab-decrypt').classList.add('active');
    toast('已发送到解密区', 'info');
  });

  $('decryptBtn').addEventListener('click', async () => {
    const token = $('decryptToken').value.trim();
    const pwd = $('decryptKey').value.trim();
    const methodChoice = $('decryptMethod').value;
    const param = $('decryptParam').value;
    if (!token) return toast('请粘贴密文 Token', 'error');

    try {
      // 尝试解析为 Token
      let meta = null;
      try { meta = parseToken(token); } catch (e) { /* 不是 Token，作为原始密文处理 */ }

      if (meta) {
        $('tokenMeta').textContent = JSON.stringify(meta, null, 2).slice(0, 500);
      }

      const effectiveMethod = methodChoice === 'auto' ? (meta ? meta.m : null) : methodChoice;
      if (!effectiveMethod) return toast('无法确定解密方式，请手动选择', 'error');

      let plain;
      if (meta) {
        plain = await decryptFromToken(meta, pwd, effectiveMethod, param);
      } else {
        plain = await decryptRaw(token, pwd, effectiveMethod, param);
      }
      $('decryptOutput').textContent = plain;
      toast('解密成功', 'success');
    } catch (e) {
      $('decryptOutput').textContent = '解密失败: ' + e.message;
      toast('解密失败: ' + e.message, 'error');
    }
  });

  async function decryptFromToken(meta, pwd, overrideMethod, param) {
    const method = overrideMethod || meta.m;
    if (method === 'aes-gcm') {
      const key = await deriveKey(pwd, fromHex(meta.s));
      return aesGcmDecrypt(b64d(meta.c), fromHex(meta.i), key);
    }
    if (method === 'aes-ctr-hmac') {
      const mac = fromHex(meta.mac);
      const ct = b64d(meta.c);
      const salt = fromHex(meta.s);
      return aesCtrHmacDecrypt(ct, fromHex(meta.i), mac, pwd, salt);
    }
    if (method === 'aes-cbc-hmac') {
      const mac = fromHex(meta.mac);
      const ct = b64d(meta.c);
      const salt = fromHex(meta.s);
      return aesCbcHmacDecrypt(ct, fromHex(meta.i), mac, pwd, salt);
    }
    if (method === 'caesar') return caesarShift(meta.c, -meta.p);
    if (method === 'vigenere') return vigenere(meta.c, meta.k, false);
    if (method === 'atbash') return atbash(meta.c);
    if (method === 'rot13') return rot13(meta.c);
    if (method === 'rot47') return rot47(meta.c);
    if (method === 'railfence') return railFence(meta.c, meta.p, false);
    if (method === 'morse') return morseDecode(meta.c);
    if (method === 'bacon') return baconDecode(meta.c);
    if (method === 'base64') return fromUtf8(b64d(meta.c));
    if (method === 'hex') return hexDecode(meta.c);
    if (method === 'binary') return binaryDecode(meta.c);
    if (method === 'octal') return octalDecode(meta.c);
    if (method === 'url') return urlDecode(meta.c);
    if (method === 'unicode') return unicodeDecode(meta.c);
    if (method === 'reverse') return meta.c.split('').reverse().join('');
    if (method === 'xor') {
      const ct = b64d(meta.c);
      const k = utf8(pwd + meta.s);
      const out = new Uint8Array(ct.length);
      for (let i=0;i<ct.length;i++) out[i] = ct[i]^k[i%k.length];
      return fromUtf8(out);
    }
    if (method === 'rc4') {
      const ct = b64d(meta.c);
      const out = rc4Bytes(ct, pwd + meta.s);
      return fromUtf8(out);
    }
    if (method === 'argon2') {
      const h = await argon2Hash($('plainText')?.value || '', fromHex(meta.s));
      return h === meta.h ? '(哈希匹配)' : '(不匹配)';
    }
    if (method === 'segmented') {
      const parts = [];
      for (const seg of meta.segments) {
        const innerMeta = parseToken('MIYU1:' + seg.d);
        const dec = await decryptFromToken(innerMeta, pwd, innerMeta.m, seg.p);
        parts.push(dec);
      }
      if (meta.raw) parts.push(fromUtf8(b64d(meta.raw)));
      return parts.join('');
    }
    throw new Error('不支持的方式: ' + method);
  }

  async function decryptRaw(text, pwd, method, param) {
    if (method === 'caesar') return caesarShift(text, -(parseInt(param)||3));
    if (method === 'vigenere') return vigenere(text, param || 'KEY', false);
    if (method === 'atbash') return atbash(text);
    if (method === 'rot13') return rot13(text);
    if (method === 'rot47') return rot47(text);
    if (method === 'railfence') return railFence(text, parseInt(param)||3, false);
    if (method === 'morse') return morseDecode(text);
    if (method === 'bacon') return baconDecode(text);
    if (method === 'base64') return fromUtf8(b64d(text));
    if (method === 'hex') return hexDecode(text);
    if (method === 'binary') return binaryDecode(text);
    if (method === 'octal') return octalDecode(text);
    if (method === 'url') return urlDecode(text);
    if (method === 'unicode') return unicodeDecode(text);
    if (method === 'reverse') return text.split('').reverse().join('');
    throw new Error('原始密文缺少元数据，请使用 Token');
  }

  /* ---------- 复制 ---------- */
  const bindCopy = (btnId, targetId) => {
    $(btnId).addEventListener('click', () => {
      const text = $(targetId).textContent;
      if (!text || text.startsWith('等待')) return toast('没有内容可复制', 'error');
      navigator.clipboard.writeText(text);
      const use = $(btnId).querySelector('use');
      use.setAttribute('href', '#i-check');
      toast('已复制', 'success');
      setTimeout(() => use.setAttribute('href', '#i-copy'), 1000);
    });
  };
  bindCopy('copyCipher', 'cipherOutput');
  bindCopy('copyPlain', 'decryptOutput');

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
    sel.innerHTML = keys.map(k => `<option value="${k.id}">${escapeHtml(k.name)} (${k.type})</option>`).join('');
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
            <button class="btn-icon" data-act="view" title="全屏查看"><svg class="icon-sm"><use href="#i-maximize"/></svg></button>
            <button class="btn-icon" data-act="export" title="导出 JSON"><svg class="icon-sm"><use href="#i-download"/></svg></button>
            <button class="btn-icon" data-act="delete" title="删除"><svg class="icon-sm"><use href="#i-trash"/></svg></button>
          </div>
        </div>
        <div class="vault-item-row">类型: ${k.type}</div>
        ${k.publicKey ? `<div class="vault-item-row">公钥: ${k.publicKey.slice(0,40)}…</div>` : ''}
        ${k.key ? `<div class="vault-item-row">密钥: ${k.key.slice(0,40)}…</div>` : ''}
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
    } else if (act === 'view') {
      const all = await dbAll(STORE_KEYS);
      const k = all.find(x => x.id === id);
      if (!k) return;
      openKeyModal(k);
    }
  });

  /* ---------- 全屏查看密钥 ---------- */
  function openKeyModal(k) {
    state.currentKeyForModal = k;
    $('modalTitle').textContent = k.name + ' · ' + k.type;
    const fields = [];
    if (k.publicKey) fields.push(['公钥 (Hex)', k.publicKey]);
    if (k.privateKey) fields.push(['私钥 (Base64)', k.privateKey]);
    if (k.key) fields.push(['子密钥 (Hex)', k.key]);
    if (k.salt) fields.push(['盐 (Hex)', k.salt]);
    if (k.info) fields.push(['用途', k.info]);
    if (k.parentId) fields.push(['父密钥 ID', k.parentId]);
    fields.push(['创建时间', new Date(k.createdAt).toLocaleString()]);
    $('modalBody').innerHTML = fields.map(([label, value]) => `
      <div class="key-field">
        <label>${escapeHtml(label)}</label>
        <div class="key-value">${escapeHtml(value)}</div>
      </div>
    `).join('');
    $('keyModal').classList.add('active');
  }

  $('modalClose').addEventListener('click', () => {
    $('keyModal').classList.remove('active');
  });
  $('keyModal').addEventListener('click', e => {
    if (e.target === $('keyModal')) $('keyModal').classList.remove('active');
  });

  $('modalCopy').addEventListener('click', () => {
    const k = state.currentKeyForModal;
    if (!k) return;
    navigator.clipboard.writeText(JSON.stringify(k, null, 2));
    toast('已复制完整密钥 JSON', 'success');
  });

  $('modalDownload').addEventListener('click', () => {
    const k = state.currentKeyForModal;
    if (!k) return;
    const blob = new Blob([JSON.stringify(k, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = k.name + '.json'; a.click();
    URL.revokeObjectURL(url);
    toast('已下载', 'success');
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
    if (!masterPwd) return toast('请先在「加密」中输入主密钥', 'error');
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
      if (!masterPwd) return toast('请先在「加密」中输入主密钥', 'error');
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
    try { meta = parseToken(target); } catch (e) { return toast('Token 格式错误', 'error'); }
    if (meta.m !== 'aes-gcm') return toast('目前只支持 AES-GCM Token 破解演示', 'error');

    state.crackAbort = false;
    $('crackBtn').disabled = true;
    $('stopCrackBtn').disabled = false;
    $('crackStatus').textContent = '破解中...';
    $('crackResult').textContent = '-';

    const start = performance.now();
    let count = 0, found = null;
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
