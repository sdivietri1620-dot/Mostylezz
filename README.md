# MoStyles (with built-in proxy)

One small Node app that serves the MoStyles start page AND a simple web proxy, so sites open inside MoStyles tabs.
No dependencies. Needs Node 18 or newer.

## Run it on your computer
1. Install Node.js from nodejs.org.
2. Open a terminal in this folder and run:  `npm start`
3. Open http://localhost:3000

## Put it online
Use any host that runs Node apps (Render, Railway, Koyeb, a VPS...). InfinityFree can't run it.
- Build command: leave empty (or `npm install`)
- Start command: `npm start`
- Add an environment variable `ACCESS_PASSWORD` with a password. STRONGLY recommended: without it, anyone who finds your link can use your proxy.

## Environment variables
- `ACCESS_PASSWORD`  asks for a password (any username) before anything loads
- `PORT`             set automatically by most hosts
- `TRUST_PROXY`      "1" (default) reads visitor IPs from X-Forwarded-For; "0" if you're not behind a host proxy
- `ALLOW_PRIVATE_NETWORK`  testing only. Never set this online.

## What works and what doesn't
Works: news sites, wikis, blogs, docs, simple search (DuckDuckGo's lite page is used for search).
Doesn't work: Instagram, Discord, YouTube, Spotify, X and other heavy apps. They need logins, live connections and anti-bot checks that a simple proxy can't handle. MoStyles shows a warning card for those with an "Open in a real tab" button.
Also not supported: logins on proxied sites (cookies are not forwarded), WebSockets, video streaming sites.

## Safety notes
- Proxied sites run on your proxy's own domain. Don't log into anything important through it.
- The proxy blocks requests to private/internal addresses so it can't be used to reach your host's internal network.
- It strips cookies in both directions and sends no referrer to the sites you visit.

## Speed tips
- Smooth mode (Yours tab) is on by default. It turns off blur, glow and extra animation.
- Free Render instances sleep after ~15 minutes idle (first load then takes ~30-50s) and have only 0.1 CPU.
  Point a free uptime pinger (like UptimeRobot) at `https://YOUR-SITE.onrender.com/healthz` every 5 minutes to keep it awake.
  `/healthz` needs no password and reveals nothing.
- The paid $7/month Render plan has 5x the CPU and never sleeps. It is the biggest speed upgrade for proxied pages.
