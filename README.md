# QR Attendance

Event check-in and check-out with QR codes. Three pages, one small server, no npm packages to install.

| Page | Who | What it does |
|---|---|---|
| `/` | Parents (public, no login) | Enter the student's code to see signed in / signed out times. No names are shown. |
| `/app` (Scan tab) | Staff and admins | Scan a QR code or type a code. First scan = time in, second = time out. |
| `/app` (Students, Team tabs) | Admins only | Import an Excel/CSV list (codes are created automatically), print QR cards, download an Excel report, manage staff accounts, see the activity log. |

## Run it on your computer
Needs Node 22.13 or newer.

    ADMIN_PASSWORD="choose-a-long-password" npm start

Open http://localhost:3000/app and sign in as `admin`. If you leave ADMIN_PASSWORD out, a random one is printed in the console on first start.

## Put it online
You need a host that runs Node (or Docker) **and gives you a persistent disk**, because the data lives in one SQLite file. Render, Railway, Fly.io, or any VPS all work.

1. Upload this folder (or push it to GitHub) and create a web service. Start command: `npm start`, or use the included Dockerfile.
2. Attach a persistent disk/volume and set `DATA_DIR` to its mount path (for example `/data`).
3. Set the environment variables from `.env.example`. Use `TRUST_PROXY=1` and `NODE_ENV=production` (this turns on HTTPS-only cookies, so the site must be served over https, which these hosts do for you).
4. Open `https://your-site/app`, sign in, and change the admin password in the Scan tab.
5. Run **one** instance only (SQLite and the login rate limits are per process).

## Excel import
Columns: **Name** (required), **Group** / Section / Grade / Class (optional), **Code** (optional; used only if unique, otherwise a code is generated). Use "Download blank template" on the Students tab.

## Security built in
- Passwords hashed with scrypt; sign-in attempts limited per IP and per username.
- Session cookie is HttpOnly, SameSite=Strict, and Secure in production; sessions expire after 12 hours and only a hash is stored.
- Roles enforced on the server: staff can only scan; every other action needs an admin.
- Parent lookup is rate-limited and has a stricter limit on wrong codes. Codes are 10 random characters, and the page returns times only (no names).
- Cross-site request protection (origin check, JSON-only requests), strict Content-Security-Policy, no framing, HSTS in production.
- Activity log of sign-ins, scans, imports, resets and account changes.

## Known limits
- The browser loads QR, scanner and Excel libraries from cdnjs.cloudflare.com. To remove that dependency, download them into `public/` and update the `<script>` tags and the CSP in `server.js`.
- Back up the `DATA_DIR` folder (the `attendance.db` file) after the event if you need a record.
