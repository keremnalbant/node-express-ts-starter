import nodemailer from 'nodemailer';

import { config } from '../config/config';
import logger from '../config/logger';

export const transport = nodemailer.createTransport({
  auth: {
    pass: config.email.smtp.auth.pass,
    user: config.email.smtp.auth.user,
  },
  service: 'icloud',
});

/* istanbul ignore next */
if (config.env !== 'test') {
  transport
    .verify()
    .then(() => logger.info('Connected to email server'))
    .catch(() => logger.warn('Unable to connect to email server. Make sure you have configured the SMTP options in .env'));
}

export const sendEmail = async ({ subject, text, to }: { subject: string; text: string; to: string }) => {
  const msg = { from: config.email.from, subject, text, to };
  await transport.sendMail(msg);
};

export const sendResetPasswordEmail = async ({ to, token }: { to: string; token: string }) => {
  const subject = 'Reset password';

  const resetPasswordUrl = `http://link-to-app/reset-password?token=${token}`;

  const text = `Dear user,
To reset your password, click on this link: ${resetPasswordUrl}
If you did not request to do that, please ignore this email.`;

  await sendEmail({ subject, text, to });
};

export const sendVerificationEmail = async ({ to, token }: { to: string; token: string }) => {
  const subject = 'Email Verification';

  const verificationEmailUrl = `http://link-to-app/verify-email?token=${token}`;

  const text = `Dear user,
To verify your email, click on this link: ${verificationEmailUrl}
If you did not create an account, then ignore this email.`;

  await sendEmail({ subject, text, to });
};
