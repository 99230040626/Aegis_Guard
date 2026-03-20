/**
 * Aegis Guard - PM2 Ecosystem Configuration
 *
 * Keeps the backend Node.js server running continuously in the background.
 *
 * Usage:
 *   cd backend
 *   npm install
 *   pm2 start ecosystem.config.js
 *   pm2 save
 *   pm2 startup   # (follow the printed command to enable on boot)
 */

module.exports = {
  apps: [
    {
      name: "aegis-guard",
      script: "server.js",
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "256M",
      env: {
        NODE_ENV: "production",
        PORT: 3000,
        SCAN_INTERVAL_MS: 8000,
      },
      env_development: {
        NODE_ENV: "development",
        PORT: 3000,
        SCAN_INTERVAL_MS: 5000,
      },
      log_date_format: "YYYY-MM-DD HH:mm:ss",
      error_file: "../logs/aegis-guard-error.log",
      out_file: "../logs/aegis-guard-out.log",
    },
  ],
};
