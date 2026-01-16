// Railway Puppeteer Configuration Fix
// Add this to the beginning of your bot.js OR run as separate file

const fs = require('fs');
const path = require('path');

console.log('🚂 Railway Environment Detection');

// Check if running on Railway
const isRailway = process.env.RAILWAY_ENVIRONMENT || 
                  process.env.RAILWAY_PROJECT_NAME || 
                  process.env.RAILWAY_SERVICE_NAME;

if (isRailway) {
    console.log('🔧 Configuring for Railway deployment');
    
    // Set puppeteer environment variables
    process.env.PUPPETEER_EXECUTABLE_PATH = '/usr/bin/google-chrome-stable';
    
    // Create required directories for bot
    const requiredDirs = [
        'data', 'data/proxies', 'data/fingerprints', 'data/sessions',
        'logs', 'cache', 'models', 'downloads', 'reports', 'screenshots'
    ];
    
    requiredDirs.forEach(dir => {
        const dirPath = path.join(__dirname, dir);
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true });
            console.log(`✅ Created directory: ${dir}`);
        }
    });
    
    // Check for environment variables
    if (!process.env.TELEGRAM_TOKEN) {
        console.error('❌ CRITICAL: TELEGRAM_TOKEN not found in Railway environment variables!');
        console.log('📝 Please add TELEGRAM_TOKEN in Railway dashboard:');
        console.log('1. Go to your Railway project');
        console.log('2. Click on your service');
        console.log('3. Go to "Variables" tab');
        console.log('4. Add TELEGRAM_TOKEN with your bot token');
        process.exit(1);
    }
    
    console.log('✅ Railway configuration complete');
}

// Export for use in bot.js
module.exports = { isRailway };