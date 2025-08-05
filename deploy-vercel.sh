#!/bin/bash

# Vercel Deployment Script for Secure Chat App
echo "🚀 Starting Vercel deployment process..."

# Check if Vercel CLI is installed
if ! command -v vercel &> /dev/null; then
    echo "📦 Installing Vercel CLI..."
    npm install -g vercel
else
    echo "✅ Vercel CLI already installed"
fi

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📁 Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit - Secure Chat App for Vercel"
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
    git commit -m "Update: Vercel deployment ready"
    git push origin main
fi

echo ""
echo "🎯 Next Steps for Vercel Deployment:"
echo ""
echo "1. 🔐 Set up External Database:"
echo "   - Go to https://railway.app"
echo "   - Create new project → 'Provision PostgreSQL'"
echo "   - Copy the connection URL"
echo ""
echo "2. 🚀 Deploy to Vercel:"
echo "   - Run: vercel login"
echo "   - Run: vercel"
echo "   - Follow the prompts"
echo ""
echo "3. ⚙️ Set Environment Variables in Vercel Dashboard:"
echo "   - SECRET_KEY=your-super-secret-key"
echo "   - DATABASE_URL=your-railway-postgres-url"
echo "   - FLASK_ENV=production"
echo ""
echo "4. 🔄 Deploy and Test:"
echo "   - Your app will be live at: https://your-app-name.vercel.app"
echo ""
echo "⚠️  Important Vercel Considerations:"
echo "   - Sessions won't work (serverless limitation)"
echo "   - Need external database (SQLite won't work)"
echo "   - Rate limiting needs external storage"
echo ""
echo "📚 For detailed instructions, see VERCEL_DEPLOYMENT.md"
echo ""
echo "💡 Recommendation: Consider Railway for better Flask support!" 