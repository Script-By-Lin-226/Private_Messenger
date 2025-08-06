#!/bin/bash

# Railway Deployment Script for Private Messenger
echo "🚀 Setting up Railway deployment..."

# Check if Railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo "📦 Installing Railway CLI..."
    npm install -g @railway/cli
else
    echo "✅ Railway CLI already installed"
fi

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📁 Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit - Private Messenger for Railway"
    git branch -M main
    echo "✅ Git repository initialized"
else
    echo "📁 Git repository already exists"
fi

# Check if remote origin exists
if ! git remote get-url origin > /dev/null 2>&1; then
    echo "🔗 Please add your GitHub repository as origin:"
    echo "   git remote add origin https://github.com/yourusername/your-repo-name.git"
    echo "   git push -u origin main"
else
    echo "🔗 Remote origin already configured"
    echo "📤 Pushing to GitHub..."
    git add .
    git commit -m "Update: Railway deployment ready"
    git push origin main
fi

echo ""
echo "🎯 Next Steps for Railway Deployment:"
echo ""
echo "1. 🚀 Deploy to Railway:"
echo "   - Go to https://railway.app"
echo "   - Click 'New Project' → 'Deploy from GitHub repo'"
echo "   - Connect your GitHub repository"
echo ""
echo "2. ⚙️ Railway will automatically:"
echo "   - Detect it's a Python app"
echo "   - Install dependencies from requirements.txt"
echo "   - Start the app with gunicorn"
echo "   - Provision PostgreSQL database"
echo ""
echo "3. 🔧 Set Environment Variables (if needed):"
echo "   - SECRET_KEY: Railway will auto-generate"
echo "   - DATABASE_URL: Railway will auto-provision"
echo ""
echo "4. 🌐 Your app will be live at:"
echo "   - https://your-app-name.railway.app"
echo ""
echo "💡 Railway is the easiest option for Flask apps!"
echo "   - No credit card required"
echo "   - Automatic PostgreSQL provisioning"
echo "   - Easy environment variable management"
echo "   - Automatic deployments from GitHub" 