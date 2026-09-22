# 🚀 IL2CPP ANALYZER — CLOUD DEPLOYMENT GUIDE

## ⚠️ Important Note Regarding Netlify ("Netfly")

**Netlify is a Jamstack & Static CDN platform.** It is designed for static websites (React, Vue, HTML/CSS) and small serverless micro-functions (AWS Lambda).

The **IL2CPP Analyzer** is a full-stack **Python Django** web application with:
1. **Large File Uploads**: Dumps and `libil2cpp.so` binaries can be 20MB–100MB+ *(Netlify has a strict 6MB serverless request limit)*.
2. **Persistent Database**: It stores indexed classes, methods, and offsets in `db.sqlite3` *(Netlify has a read-only, ephemeral filesystem)*.
3. **Binary Parsing**: Deep ELF/PE parsing and heuristic scoring take several seconds *(Netlify functions have a hard 10-second timeout)*.

---

## 🎯 Recommended Free Alternatives (Work Just Like Netlify!)

The following platforms connect directly to your **GitHub repository**, automatically build, and give you a free live HTTPS URL (e.g., `https://il2cpp-analyzer.onrender.com`):

### Option 1: Render.com (Recommended — 100% Free Tier)
Render is the backend counterpart to Netlify. We have already included a pre-configured `render.yaml` and `Procfile`.

1. Push this folder to a GitHub repository:
   ```bash
   cd d:\project\fc\il2cpp_analyzer
   git init
   git add .
   git commit -m "IL2CPP Analyzer Neo-Brutalism Release"
   git branch -M main
   git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO>.git
   git push -u origin main
   ```
2. Go to [render.com](https://render.com) and click **New +** → **Web Service**.
3. Select your GitHub repository.
4. Render will auto-detect the configuration from `render.yaml` and `Procfile`:
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt && python manage.py migrate && python manage.py collectstatic --noinput`
   - **Start Command**: `gunicorn config.wsgi:application --bind 0.0.0.0:$PORT`
5. Click **Deploy Web Service**. You will get a live URL in ~2 minutes!

---

### Option 2: Railway.app
1. Go to [railway.app](https://railway.app) and sign in with GitHub.
2. Click **New Project** → **Deploy from GitHub repo**.
3. Railway automatically detects `Procfile` and `requirements.txt` and deploys instantly.

---

### Option 3: Fly.io (Docker)
We have included a production-ready `Dockerfile`.
1. Install Fly CLI: `powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"`
2. Run `fly launch` inside `d:\project\fc\il2cpp_analyzer`.
3. Run `fly deploy`.

---

### Option 4: If You Still Want a Netlify URL
If you own a custom domain on Netlify or want a `your-name.netlify.app` address:
1. Deploy the Django backend to **Render** or **Railway**.
2. Open `netlify.toml` in this folder, uncomment the `[[redirects]]` section, and paste your Render URL:
   ```toml
   [[redirects]]
     from = "/*"
     to = "https://your-app.onrender.com/:splat"
     status = 200
     force = true
   ```
3. Connect the repository to Netlify. Netlify will act as your CDN edge proxy!
