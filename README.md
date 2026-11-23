# GreenBasket Website

A responsive GreenBasket company website starter with a home page, settings, dark/light mode, Roblox/Discord OAuth applicant login, application submission and review, and an owner-managed staff account panel.

## Important

This is a backend website project, not a GitHub Pages-only static site. OAuth secrets, staff passwords, sessions and application data require a server. Do not publish `.env` or `greenbasket.sqlite` to GitHub.

The logo image mentioned in the request was not available in the current chat attachment, so the starter uses a temporary leaf mark and illustrated produce artwork. Replace these with your supplied GreenBasket logo when you have it.

## Run locally (Windows 11)

1. Install Node.js 20 or newer.
2. Extract the project folder.
3. Open Command Prompt or PowerShell inside the `greenbasket-site` folder.
4. Run `npm install`.
5. Copy `.env.example` to a file named `.env`.
6. Edit `.env` and set `SESSION_SECRET` to a long random value, `OWNER_EMAIL`, and a strong `OWNER_PASSWORD` (12+ characters recommended).
7. Run `npm start`.
8. Open `http://localhost:3000`.

The first startup creates the owner account from the `.env` settings. Keep `.env` private. If you change the owner password in `.env` after the owner account exists, it does not automatically overwrite the database password.

## Configure Roblox OAuth

1. Open Roblox Creator Dashboard and create/register an OAuth 2.0 app.
2. Add the `openid` and `profile` scopes.
3. Set the redirect URI to `http://localhost:3000/auth/roblox/callback` while testing locally.
4. Put the Roblox client ID and secret in `.env` as `ROBLOX_CLIENT_ID` and `ROBLOX_CLIENT_SECRET`.
5. For production, add your HTTPS callback URL to Roblox and update `ROBLOX_REDIRECT_URI`.

Roblox OAuth documentation: https://create.roblox.com/docs/cloud/auth/oauth2-overview

## Configure Discord OAuth

1. Create an application in the Discord Developer Portal.
2. Under OAuth2, add the redirect URI `http://localhost:3000/auth/discord/callback`.
3. Copy the client ID and secret into `.env`.
4. For production, add your HTTPS callback URL and update `DISCORD_REDIRECT_URI`.

The website requests Discord's `identify` scope only.

## Deployment checklist

- Use a server host that supports Node.js and persistent disk/database storage.
- Set `NODE_ENV=production`, `BASE_URL` to your HTTPS domain and use HTTPS.
- Set a random `SESSION_SECRET` of at least 32 characters.
- Set all OAuth credentials and production callback URLs in the host's secret/environment settings.
- Ensure the SQLite database and session database persist across deploys and are backed up.
- Configure HTTPS, backups, log rotation, and a strict Content Security Policy before public launch.
- Review and customise the Terms and Privacy Policy to match your actual company, hosting, retention, contact and legal details before accepting real applications.

## Included routes

- `/` website
- `/terms.html` Terms of Service
- `/privacy.html` Privacy Policy
- `/auth/roblox` Roblox OAuth login
- `/auth/discord` Discord OAuth login
- `/api/staff/accounts` owner-only staff account management
- `/api/staff/applications` staff application review

The configured Roblox group ID is `616609542`.
