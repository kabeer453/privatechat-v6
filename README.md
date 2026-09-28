# PrivateChat V6

PrivateChat V6 is a mobile-first, browser-based private room messenger built from the previous V5 project.

## V6 changes

- Realtime WebSocket chat for internet/LAN deployment.
- AES-256-GCM room-key encryption in the browser.
- Encrypted JSONL message history with paginated loading instead of a 500-message server cap.
- Encrypted media stored as raw binary chunks instead of Base64 JSON WebSocket messages.
- 1 MiB encrypted media chunks, suitable for long videos and large files.
- Progressive video playback using MediaSource when the browser supports the uploaded media format; fallback buffering is used when it does not.
- WebRTC one-to-one audio calling with WebSocket signaling and a public STUN server. A TURN service is required for some restrictive networks.
- Mobile-first WhatsApp-inspired UI.
- Per-WebSocket random media access token so media endpoints are not openly accessible without a live room session.
- HTTPS/WSS-ready production behavior.

## Local development

```bat
npm install
npm run dev
```

Open `http://localhost:5173`.

For another device on the same LAN, use the host PC's LAN address, for example `http://192.168.x.x:5173`. Browser secure APIs such as microphone access generally require HTTPS on non-localhost origins.

## Production

Build the frontend:

```bat
npm run build
```

Then run the Node server:

```bat
set NODE_ENV=production
npm start
```

Put an HTTPS reverse proxy in front of the Node server and proxy WebSocket traffic for `/ws`. The browser will then automatically use `wss://` when the page is HTTPS.

## Important security note

This project uses a shared room passphrase converted into an AES-256-GCM key in each browser. The server stores ciphertext only. This is private client-side encryption, but it is **not a Signal-protocol implementation and has not been independently cryptographically audited**. Users should exchange the room passphrase and displayed security fingerprint through a trusted channel.

## Audio calls

The included audio call uses WebRTC. STUN is configured without an API key. Some mobile/carrier/corporate networks require a TURN relay for calls to connect reliably; adding TURN is the next production-hardening step.

## Media

Videos are encrypted before upload. The server receives encrypted binary chunks and never receives the plaintext video. The player attempts progressive encrypted playback through MediaSource; browser/container compatibility can still require fallback buffering.
