import express from 'express';

import * as authController from '../../controllers/auth.controller';
import { auth } from '../../middlewares/auth';
import { validate } from '../../middlewares/validate';
import * as authValidation from '../../validations/auth.validation';

const router = express.Router();

router.post('/register', validate(authValidation.registerSchema), authController.register);
router.post('/login', validate(authValidation.loginSchema), authController.login);
router.post('/logout', validate(authValidation.logoutSchema), authController.logout);
router.post('/refresh-tokens', validate(authValidation.refreshTokensSchema), authController.refreshTokens);
router.post('/forgot-password', validate(authValidation.forgotPasswordSchema), authController.forgotPassword);
router.post('/reset-password', validate(authValidation.resetPasswordSchema), authController.resetPassword);
router.post('/send-verification-email', auth(), authController.sendVerificationEmail);
router.post('/verify-email', validate(authValidation.verifyEmailSchema), authController.verifyEmail);
router.get('/me', auth(), authController.getMe);

export default router;
