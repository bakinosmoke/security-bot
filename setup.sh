#!/bin/bash

echo "╔══════════════════════════════════════════════════════╗"
echo "║   Ultimate AI Security Bot - Setup Script            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}🔍 Checking requirements...${NC}"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}❌ Node.js is not installed${NC}"
    echo "Download from: https://nodejs.org/"
    exit 1
else
    echo -e "${GREEN}✅ Node.js $(node --version)${NC}"
fi

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}❌ npm is not installed${NC}"
    exit 1
else
    echo -e "${GREEN}✅ npm $(npm --version)${NC}"
fi

echo ""
echo -e "${YELLOW}📦 Installing dependencies...${NC}"
npm install

echo ""
echo -e "${YELLOW}📁 Creating directories...${NC}"

# Create all required directories from bot.js
mkdir -p data/proxies data/fingerprints data/sessions
mkdir -p logs cache models downloads reports screenshots

echo -e "${GREEN}✅ Created all required directories${NC}"

echo ""
echo -e "${YELLOW}⚙️ Creating configuration files...${NC}"

# Create config.json if it doesn't exist
if [ ! -f config.json ]; then
    cat > config.json << 'EOL'
{
  "TELEGRAM_TOKEN": "",
  "ADMIN_IDS": [],
  "CURRENT_MODE": "educational",
  "SAFETY": {
    "MAX_LOAD_TEST_DURATION": 300,
    "MAX_SCRAPE_SIZE": 104857600,
    "RATE_LIMIT_PER_USER": 100,
    "LEGAL_COMPLIANCE_CHECK": true
  }
}
EOL
    echo -e "${GREEN}✅ Created config.json${NC}"
else
    echo -e "${YELLOW}⚠️  config.json already exists${NC}"
fi

# Create blacklist.txt if it doesn't exist
if [ ! -f blacklist.txt ]; then
    cat > blacklist.txt << 'EOL'
# Ultimate AI Security Bot - Domain Blacklist
# Add domains that should not be tested (one per line)
# Lines starting with # are comments

# Government domains (educational mode)
.gov
.mil

# Financial institutions
.bank
.pay
.wallet

# Educational institutions
.edu
.ac.uk

# Healthcare
.health
.hospital
.clinic

# Critical infrastructure
.power
.water
.energy

# Add your own restrictions below:
# example-restricted.com
# test-only.local
EOL
    echo -e "${GREEN}✅ Created blacklist.txt${NC}"
else
    echo -e "${YELLOW}⚠️  blacklist.txt already exists${NC}"
fi

# Create .env.example if it doesn't exist
if [ ! -f .env.example ]; then
    cat > .env.example << 'EOL'
# Ultimate AI Security Bot - Environment Configuration
# Copy this to .env and fill in your values

# REQUIRED: Get from @BotFather on Telegram
TELEGRAM_TOKEN=your_bot_token_here

# REQUIRED: Your Telegram user ID (get from @userinfobot)
ADMIN_IDS=123456789

# Optional: Additional admin IDs (comma-separated)
# ADMIN_IDS=123456789,987654321,555555555

# Bot operation mode
# Options: educational, research, enterprise
BOT_MODE=educational

# Safety overrides (seconds)
MAX_LOAD_TEST_DURATION=300
RATE_LIMIT_PER_USER=100

# Deployment
NODE_ENV=production
PORT=3000
EOL
    echo -e "${GREEN}✅ Created .env.example${NC}"
fi

echo ""
echo -e "${YELLOW}🔐 Security setup...${NC}"

# Make setup.sh executable
chmod +x setup.sh

# Make railway-puppeteer-fix.js if it exists
if [ -f railway-puppeteer-fix.js ]; then
    echo -e "${GREEN}✅ Railway puppeteer fix ready${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    SETUP COMPLETE!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}📋 NEXT STEPS:${NC}"
echo ""
echo "1. ${GREEN}Get your bot token:${NC}"
echo "   • Message @BotFather on Telegram"
echo "   • Use /newbot command"
echo "   • Copy the token you receive"
echo ""
echo "2. ${GREEN}Configure your bot:${NC}"
echo "   • Copy .env.example to .env:"
echo "     ${YELLOW}cp .env.example .env${NC}"
echo "   • Edit .env with your token:"
echo "     ${YELLOW}nano .env${NC} (or use any text editor)"
echo ""
echo "3. ${GREEN}Start the bot:${NC}"
echo "   ${YELLOW}npm start${NC}"
echo ""
echo "4. ${GREEN}For Railway deployment:${NC}"
echo "   • Push to GitHub"
echo "   • Create Railway project"
echo "   • Add TELEGRAM_TOKEN in Railway variables"
echo ""
echo -e "${RED}⚠️  IMPORTANT:${NC}"
echo "• Test only websites you own or have permission to test"
echo "• This is for EDUCATIONAL purposes only"
echo "• Respect all laws and regulations"
echo ""
echo -e "${GREEN}🚀 Your Ultimate AI Security Bot is ready!${NC}"