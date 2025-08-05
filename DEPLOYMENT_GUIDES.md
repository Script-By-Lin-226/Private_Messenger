# Deployment Guides for Private Messenger

## 🚀 Railway (Recommended)

**Railway** is the easiest and most reliable option for Flask apps.

### Quick Deploy:
1. Go to [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Connect your GitHub repository
4. Railway will automatically detect it's a Python app
5. Add environment variables:
   - `SECRET_KEY`: Generate a random secret key
   - `DATABASE_URL`: Railway will auto-provision PostgreSQL
6. Deploy!

### Manual Setup:
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

---

## 🌐 Render

**Render** offers free hosting with automatic deployments.

### Steps:
1. Go to [render.com](https://render.com)
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `private-messenger`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
5. Add environment variables:
   - `SECRET_KEY`: Your secret key
   - `DATABASE_URL`: Render PostgreSQL URL
6. Deploy!

---

## ⚡ Heroku

**Heroku** is a classic choice with good Flask support.

### Steps:
1. Install Heroku CLI
2. Create app:
```bash
heroku create your-app-name
heroku addons:create heroku-postgresql:mini
```

3. Set environment variables:
```bash
heroku config:set SECRET_KEY=your-secret-key
heroku config:set FLASK_ENV=production
```

4. Deploy:
```bash
git push heroku main
```

---

## 🐳 Docker (Any Platform)

Create a `Dockerfile` for containerized deployment:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
```

### Deploy with Docker:
```bash
docker build -t private-messenger .
docker run -p 8000:8000 private-messenger
```

---

## 🔧 Environment Variables

Set these environment variables on your hosting platform:

- `SECRET_KEY`: Random secret key for Flask sessions
- `DATABASE_URL`: PostgreSQL connection string (auto-provided by most platforms)
- `FLASK_ENV`: Set to `production`

---

## 📊 Database Setup

Most platforms auto-provision PostgreSQL. If not:

1. **Railway**: Auto-provisions PostgreSQL
2. **Render**: Add PostgreSQL service
3. **Heroku**: `heroku addons:create heroku-postgresql:mini`
4. **Supabase**: Free PostgreSQL hosting

---

## 🎯 Recommended Order

1. **Railway** - Easiest, most reliable
2. **Render** - Good free tier
3. **Heroku** - Classic, but requires credit card
4. **Docker** - For advanced users

---

## 🚨 Troubleshooting

### Common Issues:
- **Database connection**: Ensure `DATABASE_URL` is set
- **Port binding**: Use `gunicorn app:app` (not `flask run`)
- **Static files**: Ensure `static/` folder is included
- **Environment variables**: Check all required vars are set

### Health Check:
Visit `/health` endpoint to verify deployment is working. 