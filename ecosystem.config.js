module.exports = {
  apps: [
    {
      autorestart: true,
      instances: 1,
      name: 'server',
      script: 'dist/index.js',
      watch: false,
      env: {
        NODE_ENV: 'production',
        PORT: 3000,
        MONGODB_URL: 'mongodb://127.0.0.1:27017/node-starter',
        JWT_SECRET: 'thisisasamplesecret',
        JWT_ACCESS_EXPIRATION_MINUTES:30,
        JWT_REFRESH_EXPIRATION_DAYS:30,
        JWT_RESET_PASSWORD_EXPIRATION_MINUTES:10,
        JWT_VERIFY_EMAIL_EXPIRATION_MINUTES:10,
        SMTP_HOST:'smtp.xyz.com',
        SMTP_PORT:587,
        SMTP_USERNAME:'xyz@gmail.com',
        SMTP_PASSWORD:'********',
        EMAIL_FROM:'xyz@gmail.com'
      },
    },
  ],
};
