import rateLimit from 'express-rate-limit';

export const authLimiter = rateLimit({
  max: 20,
  skipSuccessfulRequests: true,
  windowMs: 15 * 60 * 1000,
});
