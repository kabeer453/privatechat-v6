import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const CHUNK_SIZE = 1024 * 1024;
const MAX_FILE_SIZE = 4 * 1024 * 1024 * 1024;
const PBKDF2_ITERATIONS = 600000;
const APP_VERSION = '6.0';

const Icons = {
  lock: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M7 10V8a5 5 0 0 1 10 0v2M6 10h12a1 1 0 0 1 1 1v9H5v-9a1 1 0 0 1 1-1Z"/><path d="M12 14v3"/></svg>,
  send: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="m3 20 18-8L3 4l2.5 7.2L14 12l-8.5.8L3 20Z"/></svg>,
  paperclip: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="m20.5 11.5-8.9 8.9a5 5 0 0 1-7.1-7.1l9.6-9.6a3.5 3.5 0 0 1 5 5l-9.7 9.7a2 2 0 0 1-2.8-2.8l8.9-8.9"/></svg>,
  smile: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><circle cx="12" cy="12" r="9"/><path d="M8 10h.01M16 10h.01M8.5 14.2a4.5 4.5 0 0 0 7 0"/></svg>,
  search: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><circle cx="11" cy="11" r="6.5"/><path d="m16 16 5 5"/></svg>,
  more: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><circle cx="6" cy="12" r="1.25"/><circle cx="12" cy="12" r="1.25"/><circle cx="18" cy="12" r="1.25"/></svg>,
  video: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><rect x="3" y="6" width="13" height="12" rx="2"/><path d="m16 10 5-3v10l-5-3"/></svg>,
  image: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9" r="1.5"/><path d="m4 18 5-5 3.5 3 2.5-3 5 5"/></svg>,
  file: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M8 13h8M8 17h6"/></svg>,
  shield: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="M12 3 20 6v5c0 5.1-3.2 8.6-8 10-4.8-1.4-8-4.9-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.9-5"/></svg>,
  close: (p={}) => <svg viewBox="0 0 24 24" aria-hidden="true" {...p}><path d="m6 6 12 12M18 6 6 18"/></svg>
};

function toB64(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < arr.length; i += 0x8000) s += String.fromCharCode(...arr.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(s) {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function hex(bytes) { return [...bytes].map(x => x.toString(16).padStart(2, '0')).join(''); }
function shortTime(ts) { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
function dayKey(ts) { const d = new Date(ts); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; }
function dateLabel(ts) {
  const d = new Date(ts);
  const now = new Date();
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (dayKey(ts) === dayKey(now.getTime())) return 'TODAY';
  if (dayKey(ts) === dayKey(yesterday.getTime())) return 'YESTERDAY';
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' }).toUpperCase();
}
function formatSize(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
function normalizeRoom(room) { return room.trim(); }

async function deriveRoomKey(password, room) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = enc.encode(`PrivateChatV6|${room}`);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, base, 256);
  const raw = new Uint8Array(bits);
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const fpBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', raw));
  const fingerprint = hex(fpBytes).slice(0, 24).match(/.{1,4}/g).join('-').toUpperCase();
  raw.fill(0);
  return { key, fingerprint };
}

async function encryptPayload(key, value, aadLabel) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(aadLabel);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, new TextEncoder().encode(value));
  return { v: APP_VERSION, iv: toB64(iv), data: toB64(data) };
}
async function decryptPayload(key, payload, aadLabel) {
  if (!payload || payload.v !== APP_VERSION) throw new Error('Unsupported encrypted payload');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(payload.iv), additionalData: new TextEncoder().encode(aadLabel) }, key, fromB64(payload.data));
  return new TextDecoder().decode(plain);
}


const HISTORY_DB = 'PrivateChatV6History';
const HISTORY_STORE = 'sessions';
const HISTORY_KEY = 'last-session';
const LOCAL_HISTORY_LIMIT = 5000;

function openHistoryDb() {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in window)) return reject(new Error('IndexedDB unavailable'));
    const req = indexedDB.open(HISTORY_DB, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(HISTORY_STORE)) req.result.createObjectStore(HISTORY_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
  });
}

async function readSavedSession() {
  const db = await openHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(HISTORY_STORE, 'readonly');
    const req = tx.objectStore(HISTORY_STORE).get(HISTORY_KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error || new Error('IndexedDB read failed'));
    tx.oncomplete = () => db.close();
    tx.onerror = () => { db.close(); reject(tx.error || new Error('IndexedDB transaction failed')); };
  });
}

async function saveSession(session) {
  const db = await openHistoryDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(HISTORY_STORE, 'readwrite');
    tx.objectStore(HISTORY_STORE).put({ ...session, id: HISTORY_KEY, updatedAt: Date.now() }, HISTORY_KEY);
    tx.oncomplete = () => { db.close(); resolve(true); };
    tx.onerror = () => { db.close(); reject(tx.error || new Error('IndexedDB write failed')); };
  });
}

async function clearSavedSession() {
  try {
    const db = await openHistoryDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(HISTORY_STORE, 'readwrite');
      tx.objectStore(HISTORY_STORE).delete(HISTORY_KEY);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error || new Error('IndexedDB delete failed'));
    });
    db.close();
  } catch (_) {}
}

function messageId(msg) {
  return String(msg?.id || `${msg?.userId || 'u'}-${msg?.ts || 0}-${msg?.payload?.iv || ''}`);
}

function dedupeMessages(list) {
  const map = new Map();
  for (const msg of list || []) {
    if (!msg || msg.type !== 'chat' || !msg.payload) continue;
    map.set(messageId(msg), msg);
  }
  return [...map.values()].sort((a, b) => Number(a.ts || 0) - Number(b.ts || 0)).slice(-LOCAL_HISTORY_LIMIT);
}

function App() {
  const [joined, setJoined] = useState(false);
  const [name, setName] = useState(localStorage.getItem('pc_name') || '');
  const [room, setRoom] = useState('');
  const [password, setPassword] = useState('');
  const [key, setKey] = useState(null);
  const [fingerprint, setFingerprint] = useState('');
  const [status, setStatus] = useState('Offline');
  const [online, setOnline] = useState(0);
  const [users, setUsers] = useState([]);
  const [accessToken, setAccessToken] = useState('');
  const [callPeer, setCallPeer] = useState(null);
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState('');
  const [uploading, setUploading] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [search, setSearch] = useState('');
  const ws = useRef(null);
  const bottom = useRef(null);
  const userId = useMemo(() => {
    const saved = localStorage.getItem('pc_device_id');
    if (saved) return saved;
    const id = crypto.randomUUID();
    localStorage.setItem('pc_device_id', id);
    return id;
  }, []);
  const [restoring, setRestoring] = useState(true);
  const callRef = useRef({ pc: null, stream: null, peerId: '', incoming: false });

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => () => ws.current?.close(), []);

  useEffect(() => {
    let cancelled = false;
    async function restore() {
      try {
        const saved = await readSavedSession();
        if (!saved || cancelled || !saved.key || !saved.room) {
          if (!cancelled) setRestoring(false);
          return;
        }
        setName(saved.name || localStorage.getItem('pc_name') || '');
        setRoom(saved.room);
        setFingerprint(saved.fingerprint || '');
        setKey(saved.key);
        const restored = [];
        for (const msg of saved.messages || []) {
          try {
            const plain = await decryptPayload(saved.key, msg.payload, 'pc6:message');
            restored.push({ ...msg, text: plain, self: msg.userId === userId });
          } catch (_) {}
        }
        if (cancelled) return;
        setMessages(restored);
        setJoined(true);
        connect(saved.key, saved.name || 'Anonymous', saved.room, saved.fingerprint || '');
      } catch (err) {
        console.warn('Saved private chat session could not be restored', err);
      } finally {
        if (!cancelled) setRestoring(false);
      }
    }
    restore();
    return () => { cancelled = true; };
  }, []);

  async function persistMessages(nextMessages, sessionOverride = {}) {
    const encryptedMessages = dedupeMessages(nextMessages).map(m => ({
      id: m.id, name: m.name, userId: m.userId, payload: m.payload, ts: Number(m.ts || Date.now())
    }));
    try {
      await saveSession({
        room: sessionOverride.room || room,
        name: sessionOverride.name || name,
        fingerprint: sessionOverride.fingerprint || fingerprint,
        key: sessionOverride.key || key,
        messages: encryptedMessages
      });
    } catch (err) {
      console.warn('Encrypted local chat history could not be saved', err);
    }
  }

  async function handleJoin(e) {
    e?.preventDefault();
    if (!window.isSecureContext) {
      alert('PrivateChat needs a secure HTTPS page on non-localhost devices. Deploy the app with HTTPS before using it on the internet.');
      return;
    }
    if (!name.trim() || !room.trim() || password.length < 12) {
      alert('Enter your name, room code, and a passphrase of at least 12 characters. Use a strong private passphrase and share it only with the people you trust.');
      return;
    }
    try {
      const cleanRoom = normalizeRoom(room);
      setStatus('Generating security key…');
      const result = await deriveRoomKey(password, cleanRoom);
      localStorage.setItem('pc_name', name.trim());
      setKey(result.key);
      setFingerprint(result.fingerprint);
      setRoom(cleanRoom);
      setJoined(true);
      await saveSession({ room: cleanRoom, name: name.trim(), fingerprint: result.fingerprint, key: result.key, messages: [] });
      connect(result.key, name.trim(), cleanRoom, result.fingerprint);
    } catch (err) {
      console.error(err);
      alert('Could not create the encryption key on this device.');
      setStatus('Offline');
    }
  }

  function connect(k, n, r, fp = '') {
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${location.host}/ws?room=${encodeURIComponent(r)}`);
    ws.current = socket;
    setStatus('Connecting…');
    socket.onopen = () => {
      setStatus('Online');
      socket.send(JSON.stringify({ type: 'join', name: n, userId }));
    };
    socket.onmessage = async event => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'session') { setAccessToken(msg.token || ''); return; }
        if (msg.type === 'presence') { setOnline(Number(msg.count || 0)); setUsers(Array.isArray(msg.users) ? msg.users : []); return; }
        if (msg.type === 'signal') { handleSignal(msg); return; }
        if (msg.type === 'history') {
          const history = [];
          for (const item of Array.isArray(msg.messages) ? msg.messages : []) {
            try { const plain = await decryptPayload(k, item.payload, 'pc6:message'); history.push({ ...item, type: 'chat', text: plain, self: item.userId === userId }); } catch (_) {}
          }
          setMessages(v => {
            const merged = dedupeMessages([...v.filter(x => x.type === 'chat'), ...history]);
            const withSelf = merged.map(x => ({ ...x, text: x.text || '', self: x.userId === userId }));
            queueMicrotask(() => persistMessages(withSelf, { key: k, room: r, name: n, fingerprint: fp }));
            return withSelf;
          });
          return;
        }
        if (msg.type === 'system') return;
        if (msg.type === 'chat') {
          const plain = await decryptPayload(k, msg.payload, 'pc6:message');
          setMessages(v => {
            const merged = dedupeMessages([...v.filter(x => x.type === 'chat'), { ...msg, text: plain, self: msg.userId === userId }]);
            const withSelf = merged.map(x => ({ ...x, self: x.userId === userId }));
            queueMicrotask(() => persistMessages(withSelf, { key: k, room: r, name: n, fingerprint: fp }));
            return withSelf;
          });
        }
      } catch (err) { console.warn('Incoming event rejected', err); }
    };
    socket.onclose = () => { setStatus('Disconnected'); setOnline(0); setUsers([]); setAccessToken(''); endCall(false); };
    socket.onerror = () => setStatus('Connection error');
  }

  async function sendSignal(to, signal) {
    if (ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify({ type: 'signal', to, signal }));
  }

  async function startCall(peer) {
    if (!peer || peer.id === userId || callRef.current.pc) return;
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
      const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      callRef.current = { pc, stream, peerId: peer.id, incoming: false };
      stream.getTracks().forEach(track => pc.addTrack(track, stream));
      pc.onicecandidate = e => { if (e.candidate) sendSignal(peer.id, { type: 'ice', candidate: e.candidate }); };
      pc.onconnectionstatechange = () => { if (['failed','disconnected','closed'].includes(pc.connectionState)) endCall(false); };
      pc.ontrack = e => { const audio = document.getElementById('pc6-call-audio'); if (audio) { audio.srcObject = e.streams[0]; audio.play().catch(()=>{}); } };
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendSignal(peer.id, { type: 'offer', sdp: offer });
      setCallPeer({ ...peer, state: 'calling' });
    } catch (e) { console.error(e); alert('Microphone access is required for an audio call.'); endCall(false); }
  }

  async function handleSignal(msg) {
    const s = msg.signal || {};
    try {
      if (s.type === 'offer') {
        if (callRef.current.pc) return;
        const peer = { id: msg.from, name: msg.name || 'PrivateChat user' };
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        callRef.current = { pc, stream, peerId: peer.id, incoming: true };
        stream.getTracks().forEach(track => pc.addTrack(track, stream));
        pc.onicecandidate = e => { if (e.candidate) sendSignal(peer.id, { type: 'ice', candidate: e.candidate }); };
        pc.onconnectionstatechange = () => { if (['failed','disconnected','closed'].includes(pc.connectionState)) endCall(false); };
        pc.ontrack = e => { const audio = document.getElementById('pc6-call-audio'); if (audio) { audio.srcObject = e.streams[0]; audio.play().catch(()=>{}); } };
        await pc.setRemoteDescription(s.sdp);
        const answer = await pc.createAnswer(); await pc.setLocalDescription(answer);
        await sendSignal(peer.id, { type: 'answer', sdp: answer });
        setCallPeer({ ...peer, state: 'connected' });
      } else if (s.type === 'answer' && callRef.current.pc) {
        await callRef.current.pc.setRemoteDescription(s.sdp); setCallPeer(v => v ? { ...v, state: 'connected' } : v);
      } else if (s.type === 'ice' && callRef.current.pc) {
        await callRef.current.pc.addIceCandidate(s.candidate);
      } else if (s.type === 'hangup') {
        endCall(false);
      }
    } catch (e) { console.warn('Call signal failed', e); endCall(false); }
  }

  function endCall(notify = true) {
    const c = callRef.current;
    if (notify && c.peerId) sendSignal(c.peerId, { type: 'hangup' });
    try { c.stream?.getTracks().forEach(t => t.stop()); c.pc?.close(); } catch (_) {}
    callRef.current = { pc: null, stream: null, peerId: '', incoming: false };
    const audio = document.getElementById('pc6-call-audio'); if (audio) audio.srcObject = null;
    setCallPeer(null);
  }

  async function sendMessage() {
    const value = text.trim();
    if (!value || !key || !ws.current || ws.current.readyState !== WebSocket.OPEN) return;
    const ts = Date.now();
    const payload = await encryptPayload(key, value, 'pc6:message');
    ws.current.send(JSON.stringify({ type: 'chat', id: crypto.randomUUID(), name, userId, payload, ts }));
    setText('');
  }

  async function sendFile(file) {
    if (!file || !key || uploading || !ws.current || ws.current.readyState !== WebSocket.OPEN || !accessToken) return;
    if (file.size > MAX_FILE_SIZE) return alert(`Maximum file size is ${formatSize(MAX_FILE_SIZE)}.`);
    setUploading(true);
    try {
      const fileId = crypto.randomUUID();
      const total = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
      for (let i = 0; i < total; i++) {
        const chunk = await file.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, file.size)).arrayBuffer();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`pc6:file:${fileId}:${i}`) }, key, chunk);
        const res = await fetch('/api/upload-binary', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/octet-stream',
            'X-Chat-Room': room,
            'X-Chat-Token': accessToken,
            'X-File-Id': fileId,
            'X-File-Index': String(i),
            'X-File-Total': String(total),
            'X-File-IV': toB64(iv)
          },
          body: encrypted
        });
        if (!res.ok) throw new Error(`upload ${res.status}`);
        setStatus(`Uploading ${Math.round(((i + 1) / total) * 100)}%`);
      }
      setStatus('Online');
      const metadata = JSON.stringify({ kind: 'file', id: fileId, name: file.name, mime: file.type || 'application/octet-stream', size: file.size, total, version: 1 });
      const payload = await encryptPayload(key, metadata, `pc6:file-meta:${fileId}`);
      ws.current.send(JSON.stringify({ type: 'chat', id: crypto.randomUUID(), name, userId, payload, ts: Date.now() }));
    } catch (err) { console.error(err); alert('The encrypted upload failed. Check the connection and try again.'); setStatus('Online'); }
    finally { setUploading(false); }
  }

  async function leaveRoom() {
    ws.current?.close();
    await clearSavedSession();
    setJoined(false);
    setKey(null);
    setFingerprint('');
    setMessages([]);
    setOnline(0);
    setUsers([]);
    setAccessToken('');
    endCall(false);
    setPassword('');
    setRoom('');
  }

  if (restoring) {
    return <div className="restore-page"><div className="restore-card"><div className="brand-lock"><Icons.lock /></div><strong>Opening your private chats…</strong><span>Restoring encrypted history on this device.</span></div></div>;
  }

  if (!joined) {
    return <SetupScreen name={name} setName={setName} room={room} setRoom={setRoom} password={password} setPassword={setPassword} onJoin={handleJoin} />;
  }

  const visibleMessages = search.trim()
    ? messages.filter(m => String(m.text || '').toLowerCase().includes(search.toLowerCase()))
    : messages;
  let previousDay = '';
  const renderedMessages = visibleMessages.map((m, i) => {
    const currentDay = dayKey(m.ts);
    const showDay = currentDay !== previousDay;
    previousDay = currentDay;
    return <React.Fragment key={`${messageId(m)}-${i}`}>
      {showDay && <div className="date-chip">{dateLabel(m.ts)}</div>}
      <div className={`message-row ${m.self ? 'outgoing' : 'incoming'}`}>
        <div className="message-bubble">
          {!m.self && <div className="sender-name">{m.name}</div>}
          <MessageContent encryptedText={m.text} room={room} keyObj={key} accessToken={accessToken} />
          <div className="message-time">{shortTime(m.ts)} {m.self && <span className="ticks">✓✓</span>}</div>
        </div>
      </div>
    </React.Fragment>;
  });

  return <div className="wa-app">
    <aside className="wa-sidebar">
      <div className="sidebar-top">
        <div className="avatar self-avatar">{(name[0] || 'P').toUpperCase()}</div>
        <div className="sidebar-title">PrivateChat</div>
        <button className="icon-btn" onClick={() => setSecurityOpen(true)} aria-label="Security"><Icons.lock /></button>
        <button className="icon-btn" onClick={leaveRoom} aria-label="Leave room"><Icons.more /></button>
      </div>
      <div className="security-card">
        <Icons.shield />
        <div><strong>End-to-end encrypted</strong><span>Messages and media are encrypted before they leave your device. Encrypted history is saved for reopening.</span></div>
      </div>
      <div className="search-box"><Icons.search /><span>Private room</span></div>
      <div className="room-list"><div className="room-item active"><div className="avatar room-avatar">🔒</div><div><strong>Private room</strong><span>{room}</span></div><em>{online} online</em></div></div>
    </aside>

    <section className="wa-chat">
      <header className="chat-header">
        <div className="mobile-avatar"><div className="avatar room-avatar">🔒</div></div>
        <div className="chat-contact"><strong>Private room</strong><span><b className={status === 'Online' ? 'online-dot' : ''}></b>{online} online · End-to-end encrypted</span></div>
        <div className="chat-actions">
          {searchOpen && <input autoFocus className="mini-search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search" />}
          <button className="icon-btn" onClick={() => setSearchOpen(v => !v)} aria-label="Search"><Icons.search /></button>
          <button className="icon-btn" onClick={() => setSecurityOpen(true)} aria-label="Security"><Icons.lock /></button>
        </div>
      </header>

      <div className="call-strip">
        <span>👥 {online} online</span>
        {users.filter(u => u.id !== userId).slice(0, 6).map(u => <button key={u.id} onClick={() => startCall(u)} disabled={!!callPeer}>📞 {u.name}</button>)}
      </div>
      <main className="chat-body">
        {messages.length >= LOCAL_HISTORY_LIMIT && <button className="load-more" onClick={() => { const oldest = messages.filter(m => m.type === 'chat').sort((a,b)=>a.ts-b.ts)[0]; if (oldest && ws.current?.readyState === WebSocket.OPEN) ws.current.send(JSON.stringify({ type: 'historyMore', before: oldest.ts })); }}>Load older encrypted messages</button>}
        <div className="encryption-note"><span className="note-lock"><Icons.lock /></span><div><strong>Messages and calls are end-to-end encrypted.</strong><span>Only people in this room with the same passphrase can decrypt the content.</span></div></div>
        {visibleMessages.length === 0 && <div className="empty-chat"><div className="empty-icon"><Icons.shield /></div><strong>{search.trim() ? 'No matching messages' : 'Your private room is ready'}</strong><span>{search.trim() ? 'Try another search term.' : 'Send a message or attach a video. Your encrypted history will remain available when you reopen the app.'}</span></div>}
        {renderedMessages}
        <div ref={bottom} />
      </main>

      <div className="composer-wrap">
        {uploading && <div className="upload-progress"><span className="spinner"></span>Encrypting and uploading securely…</div>}
        <div className="composer">
          <button className="icon-btn composer-icon" aria-label="Emoji"><Icons.smile /></button>
          <label className="icon-btn composer-icon" aria-label="Attach file"><Icons.paperclip /><input type="file" accept="video/*,image/*,audio/*,.pdf,.doc,.docx,.txt" disabled={uploading} onChange={e => { sendFile(e.target.files?.[0]); e.target.value = ''; }} /></label>
          <input className="message-input" value={text} onChange={e => setText(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }} placeholder="Type a message" />
          <button className="send-btn" onClick={sendMessage} disabled={!text.trim() || status !== 'Online'} aria-label="Send"><Icons.send /></button>
        </div>
      </div>
    </section>

    {callPeer && <div className="call-overlay"><div className="call-card"><div className="call-avatar">{(callPeer.name?.[0] || '?').toUpperCase()}</div><strong>{callPeer.name}</strong><span>{callPeer.state === 'calling' ? 'Calling…' : 'Audio call connected'}</span><audio id="pc6-call-audio" autoPlay playsInline /><button className="hangup-btn" onClick={() => endCall(true)}>End call</button></div></div>}
    {securityOpen && <SecurityModal fingerprint={fingerprint} room={room} onClose={() => setSecurityOpen(false)} />}
  </div>;
}

function SetupScreen({ name, setName, room, setRoom, password, setPassword, onJoin }) {
  const secure = window.isSecureContext;
  return <div className="setup-page">
    <div className="setup-glow glow-one"></div><div className="setup-glow glow-two"></div>
    <div className="setup-card">
      <div className="brand-lock"><Icons.shield /></div>
      <div className="brand-name">Private<span>Chat</span></div>
      <h1>Private conversations,<br /><em>built for privacy.</em></h1>
      <p className="setup-copy">WhatsApp-inspired private messaging with encrypted text, media and encrypted chat history.</p>
      <div className={`secure-status ${secure ? 'secure' : 'insecure'}`}><span></span>{secure ? 'Secure browser context' : 'HTTPS is required on network/internet addresses'}</div>
      <form onSubmit={onJoin}>
        <label>Your name<input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Abdul" autoComplete="name" /></label>
        <label>Private room code<input value={room} onChange={e => setRoom(e.target.value)} placeholder="family-2026" autoCapitalize="none" /></label>
        <label>Shared encryption passphrase<input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="12+ characters" autoComplete="new-password" /></label>
        <button className="join-btn" type="submit"><Icons.lock /> Enter encrypted room</button>
      </form>
      <div className="setup-note"><Icons.lock /><span>Your passphrase stays on your device. This browser can remember an encrypted session so your chat history can reappear when you reopen PrivateChat.</span></div>
    </div>
  </div>;
}

function SecurityModal({ fingerprint, room, onClose }) {
  return <div className="modal-backdrop" onMouseDown={onClose}>
    <div className="security-modal" onMouseDown={e => e.stopPropagation()}>
      <div className="modal-head"><div><Icons.shield /><strong>Security information</strong></div><button className="icon-btn" onClick={onClose} aria-label="Close"><Icons.close /></button></div>
      <div className="secure-big"><span></span>End-to-end encrypted</div>
      <p>PrivateChat encrypts message text, file chunks, and file metadata in the browser before they leave your device.</p>
      <div className="security-row"><span>Room</span><strong>{room}</strong></div>
      <div className="security-row"><span>Security code</span><strong className="fingerprint">{fingerprint}</strong></div>
      <div className="security-row"><span>Content cipher</span><strong>AES-256-GCM</strong></div>
      <div className="security-row"><span>Key derivation</span><strong>PBKDF2 · SHA-256 · 310,000 iterations</strong></div>
      <div className="security-warning">This is a V4 application design, not a cryptographically audited WhatsApp replacement. Always verify the security code with the other participant through a trusted channel.</div>
      <button className="close-btn" onClick={onClose}>Done</button>
    </div>
  </div>;
}

function MessageContent({ encryptedText, room, keyObj, accessToken }) {
  const [data, setData] = useState(null);
  const [mediaUrl, setMediaUrl] = useState('');
  const [state, setState] = useState('');
  const [loading, setLoading] = useState(false);
  const videoRef = useRef(null);
  const objectUrlRef = useRef('');

  useEffect(() => { let parsed = null; try { const x = JSON.parse(encryptedText); if (x?.kind === 'file') parsed = x; } catch (_) {} setData(parsed); setMediaUrl(''); setState(''); }, [encryptedText]);
  useEffect(() => () => { if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current); }, []);

  async function fetchChunk(i) {
    const res = await fetch(`/api/download/${encodeURIComponent(room)}/${encodeURIComponent(data.id)}/${i}`, { cache: 'no-store', headers: { 'X-Chat-Token': accessToken } });
    if (!res.ok) throw new Error(`media ${res.status}`);
    const iv64 = res.headers.get('x-file-iv'); if (!iv64) throw new Error('missing iv');
    const encrypted = await res.arrayBuffer();
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(iv64), additionalData: new TextEncoder().encode(`pc6:file:${data.id}:${i}`) }, keyObj, encrypted);
  }

  async function prepare() {
    if (!data || !keyObj || loading || mediaUrl) return;
    setLoading(true); setState('Preparing encrypted media…');
    try {
      const isVideo = data.mime?.startsWith('video/');
      if (isVideo && 'MediaSource' in window) {
        const ms = new MediaSource(); const url = URL.createObjectURL(ms); objectUrlRef.current = url; setMediaUrl(url);
        await new Promise(resolve => ms.addEventListener('sourceopen', resolve, { once: true }));
        const mime = data.mime;
        if (!MediaSource.isTypeSupported(mime)) throw new Error(`This browser cannot stream ${mime}`);
        const sb = ms.addSourceBuffer(mime);
        for (let i=0;i<data.total;i++) {
          const chunk = new Uint8Array(await fetchChunk(i));
          await new Promise((resolve,reject)=>{ const done=()=>{sb.removeEventListener('updateend',done);sb.removeEventListener('error',fail);resolve();}; const fail=()=>{sb.removeEventListener('updateend',done);sb.removeEventListener('error',fail);reject(new Error('media append failed'));}; sb.addEventListener('updateend',done,{once:true});sb.addEventListener('error',fail,{once:true}); sb.appendBuffer(chunk); });
          setState(`Streaming ${Math.round(((i+1)/data.total)*100)}%`);
        }
        if (ms.readyState === 'open') ms.endOfStream();
        setState('ready');
      } else {
        const parts=[]; for(let i=0;i<data.total;i++){parts.push(await fetchChunk(i));setState(`Preparing ${Math.round(((i+1)/data.total)*100)}%`);}
        const url=URL.createObjectURL(new Blob(parts,{type:data.mime||'application/octet-stream'})); objectUrlRef.current=url; setMediaUrl(url); setState('ready');
      }
    } catch(e){ console.error(e); if(objectUrlRef.current){URL.revokeObjectURL(objectUrlRef.current);objectUrlRef.current='';} setMediaUrl(''); setState('Unable to decrypt or stream this media.'); }
    finally { setLoading(false); }
  }

  if (!data) return <div className="message-text">{encryptedText}</div>;
  const isVideo=data.mime?.startsWith('video/'), isImage=data.mime?.startsWith('image/'), isAudio=data.mime?.startsWith('audio/');
  return <div className="media-message">
    {isVideo && mediaUrl ? <div className="video-frame"><video ref={videoRef} src={mediaUrl} controls playsInline preload="metadata" controlsList="nodownload" onContextMenu={e=>e.preventDefault()} /></div> : null}
    {isImage && mediaUrl ? <img className="image-preview" src={mediaUrl} alt={data.name} /> : null}
    {isAudio && mediaUrl ? <audio className="audio-preview" src={mediaUrl} controls controlsList="nodownload" /> : null}
    {!mediaUrl && <button className={`media-load-card ${loading?'loading':''}`} onClick={prepare} disabled={loading}><span className="media-load-icon">{isVideo?<Icons.video/>:isImage?<Icons.image/>:isAudio?<Icons.video/>:<Icons.file/>}</span><span><strong>{loading?state:(isVideo?'Tap to stream video':isImage?'Tap to view image':isAudio?'Tap to play audio':'Tap to open file')}</strong><small>{formatSize(data.size)} · Encrypted on this device</small></span><span className="media-load-arrow">›</span></button>}
    <div className="media-caption"><div className="media-type-icon">{isVideo?<Icons.video/>:isImage?<Icons.image/>:<Icons.file/>}</div><div><strong>{data.name}</strong><span>{formatSize(data.size)} · {isVideo?'Progressive encrypted playback':'Encrypted media'}</span></div></div>
  </div>;
}

createRoot(document.getElementById('root')).render(<App />);
