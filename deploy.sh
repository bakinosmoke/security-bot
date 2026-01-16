#!/bin/bash

echo "🚀 Ultimate AI Security Bot - Deployment Script"

# Step 1: Revoke old token if exposed
echo "🔐 Step 1: Security Check"
if grep -q "8586971478:AAE6fd8BIC2geLWSiKYYYLYEU9FB1OjjK_c" bot.js; then
    echo "❌ OLD TOKEN DETECTED IN CODE!"
    echo "⚠️  Please revoke this token at @BotFather immediately!"
    read -p "Have you revoked the token? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Deployment cancelled. Please revoke token first."
        exit 1
    fi
fi

# Step 2: Setup
echo "📦 Step 2: Setup"
./setup.sh

# Step 3: Check .env
echo "🔧 Step 3: Check Configuration"
if [ ! -f .env ]; then
    echo "⚠️  No .env file found"
    cp .env.example .env
    echo "✅ Created .env from template"
    echo "📝 Please edit .env with your Telegram token"
    nano .env
fi

# Step 4: Test
echo "🧪 Step 4: Test Bot"
echo "Starting bot in test mode (Ctrl+C to stop)..."
node bot.js --test || echo "❌ Test failed, check configuration"

# Step 5: Git setup
echo "📁 Step 5: Git Setup"
read -p "Initialize git repository? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git init
    git add .
    git commit -m "Initial commit: Ultimate AI Security Bot"
    
    read -p "Create GitHub repository? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🌐 Create a new repository at: https://github.com/new"
        echo "Then run:"
        echo "  git remote add origin https://github.com/yourusername/ultimate-ai-security-bot.git"
        echo "  git branch -M main"
        echo "  git push -u origin main"
    fi
fi

echo ""
echo "✅ Deployment setup complete!"
echo ""
echo "🚀 For Railway deployment:"
echo "1. Push to GitHub"
echo "2. Go to https://railway.app"
echo "3. Create new project"
echo "4. Deploy from GitHub"
echo "5. Add TELEGRAM_TOKEN in Railway variables"
echo ""
echo "🤖 Bot ready to deploy!"