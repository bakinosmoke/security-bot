# 🚀 Setup Guide

## 1. Get Telegram Bot Token
1. Open Telegram, search for @BotFather
2. Send `/newbot`
3. Choose name and username
4. Copy the token (looks like: `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`)

## 2. Local Setup
```bash
git clone https://github.com/yourusername/ultimate-ai-security-bot.git
cd ultimate-ai-security-bot
npm install
cp .env.example .env
# Edit .env with your token
npm start