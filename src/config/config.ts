import path from 'path';

import * as dotenv from 'dotenv';
import Joi from 'joi';

dotenv.config({ path: path.join(__dirname, '../../.env') });

const envVarsSchema = Joi.object()
  .keys({
    JWT_ACCESS_EXPIRATION_MINUTES: Joi.number()
    .default(30)
    .description('minutes after which access tokens expire')
    .required(),
    JWT_REFRESH_EXPIRATION_DAYS: Joi.number().default(30).description('days after which refresh tokens expire').required(),
    JWT_RESET_PASSWORD_EXPIRATION_MINUTES: Joi.number()
    .default(10)
    .description('minutes after which reset password token expires')
    .required(),
    JWT_SECRET: Joi.string().description('JWT secret key').required(),
    JWT_VERIFY_EMAIL_EXPIRATION_MINUTES: Joi.number()
    .default(10)
    .description('minutes after which verify email token expires')
    .required(),
    MONGODB_URL: Joi.string().description('Mongo DB url').required(),
    NODE_ENV: Joi.string().valid('production', 'development', 'test').required(),
    PORT: Joi.number().default(3000).required(),
    EMAIL_FROM: Joi.string().description('the from field in the emails sent by the app').required(),
    SMTP_HOST: Joi.string().description('server that will send the emails').required(),
    SMTP_PASSWORD: Joi.string().description('password for email server').required(),
    SMTP_PORT: Joi.number().description('port to connect to the email server').required(),
    SMTP_USERNAME: Joi.string().description('username for email server').required(),
  })
  .unknown();

const { error, value: envVars } = envVarsSchema.prefs({ errors: { label: 'key' } }).validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

export const config = {
  email: {
    from: envVars.EMAIL_FROM,
    smtp: {
      auth: {
        pass: envVars.SMTP_PASSWORD,
        user: envVars.SMTP_USERNAME,
      },
      host: envVars.SMTP_HOST,
      port: envVars.SMTP_PORT,
    },
  },
  env: envVars.NODE_ENV,
  jwt: {
    accessExpirationMinutes: envVars.JWT_ACCESS_EXPIRATION_MINUTES,
    refreshExpirationDays: envVars.JWT_REFRESH_EXPIRATION_DAYS,
    resetPasswordExpirationMinutes: envVars.JWT_RESET_PASSWORD_EXPIRATION_MINUTES,
    secret: envVars.JWT_SECRET,
    verifyEmailExpirationMinutes: envVars.JWT_VERIFY_EMAIL_EXPIRATION_MINUTES,
  },
  mongoose: {
    url: envVars.MONGODB_URL,
  },
  port: envVars.PORT,
};
