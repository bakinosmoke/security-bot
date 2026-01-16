#!/bin/bash
echo "🚀 Deploying to Railway..."
git add .
git commit -m "Deploy update"
git push origin main
echo "✅ Pushed to GitHub. Railway will auto-deploy!"
echo "📊 Check status: https://railway.app/project/YOUR_PROJECT_ID"