#!/bin/bash

echo "🚀 Ultimate AI Security Bot - Deployment Script"

# Step 1: Generate package-lock.json
echo "📦 Step 1: Generating package-lock.json"
if [ ! -f "package-lock.json" ]; then
    npm install
    echo "✅ Created package-lock.json"
else
    echo "✅ package-lock.json already exists"
fi

# Step 2: Setup
echo "📦 Step 2: Setup"
chmod +x setup.sh
./setup.sh

# Step 3: Check .env
echo "🔧 Step 3: Check Configuration"
if [ ! -f .env ]; then
    echo "⚠️  No .env file found"
    cp .env.example .env
    echo "✅ Created .env from template"
    echo "📝 Please edit .env with your Telegram token"
    echo ""
    echo "Edit .env file and add:"
    echo "TELEGRAM_TOKEN=your_bot_token_here"
    echo "ADMIN_IDS=your_telegram_id"
    echo ""
    read -p "Press Enter to continue after editing .env file..."
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
    
    echo ""
    echo "🌐 Create a new repository at: https://github.com/new"
    echo "Then run these commands:"
    echo ""
    echo "  git remote add origin https://github.com/yourusername/ultimate-ai-security-bot.git"
    echo "  git branch -M main"
    echo "  git push -u origin main"
    echo ""
    read -p "Have you created the GitHub repository? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Please run the git commands above to push to GitHub"
    fi
fi

echo ""
echo "✅ Deployment setup complete!"
echo ""
echo "🚀 For Railway deployment:"
echo "1. Push to GitHub:"
echo "   git push origin main"
echo "2. Go to https://railway.app"
echo "3. Create new project"
echo "4. Deploy from GitHub"
echo "5. Add these variables in Railway:"
echo "   - TELEGRAM_TOKEN (your bot token)"
echo "   - ADMIN_IDS (your Telegram ID)"
echo "   - RAILWAY_ENVIRONMENT=true"
echo "6. Wait for deployment to complete"
echo ""
echo "🤖 Bot ready to deploy!"
