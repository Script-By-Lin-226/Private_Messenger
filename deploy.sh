#!/bin/bash

# Deployment Script for Secure Chat App
echo "🚀 Starting deployment process..."

# Check if git is initialized
if [ ! -d ".git" ]; then
    echo "📁 Initializing git repository..."
    git init
    git add .
    git commit -m "Initial commit - Secure Chat App"
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
    git commit -m "Update: Security improvements and deployment ready"
    git push origin main
fi

echo ""
echo "🎯 Next Steps:"
echo "1. Go to https://railway.app"
echo "2. Click 'New Project'"
echo "3. Select 'Deploy from GitHub repo'"
echo "4. Choose your repository"
echo "5. Set environment variables:"
echo "   - SECRET_KEY=your-super-secret-key"
echo "   - FLASK_ENV=production"
echo "   - DATABASE_URL=your-railway-postgres-url"
echo ""
echo "🌐 Your app will be live at: https://your-app-name.railway.app"
echo ""
echo "📚 For detailed instructions, see DEPLOYMENT.md" 