import httpStatus from 'http-status';

import * as authService from '../services/auth.service';
import * as emailService from '../services/email.service';
import * as tokenService from '../services/token.service';
import * as userService from '../services/user.service';
import { catchAsync } from '../utils/catchAsync';

export const register = catchAsync(async (req, res) => {
  const user = await userService.createUser(req.body);
  const tokens = await tokenService.generateAuthTokens(user);
  res.status(httpStatus.CREATED).send({ tokens, user });
});

export const login = catchAsync(async (req, res) => {
  const { email, password } = req.body;
  const user = await authService.loginUserWithEmailAndPassword(email, password);
  const tokens = await tokenService.generateAuthTokens(user);
  res.send({ tokens, user });
});

export const logout = catchAsync(async (req, res) => {
  await authService.logout(req.body.refreshToken);
  res.status(httpStatus.NO_CONTENT).send();
});

export const refreshTokens = catchAsync(async (req, res) => {
  const tokens = await authService.refreshAuth(req.body.refreshToken);
  res.send({ ...tokens });
});

export const forgotPassword = catchAsync(async (req, res) => {
  const resetPasswordToken = await tokenService.generateResetPasswordToken(req.body.email);
  await emailService.sendResetPasswordEmail({ to: req.body.email, token: resetPasswordToken });
  res.status(httpStatus.NO_CONTENT).send();
});

export const resetPassword = catchAsync(async (req, res) => {
  await authService.resetPassword({ newPassword: req.body.password, resetPasswordToken: req.query.token as string });
  res.status(httpStatus.NO_CONTENT).send();
});

export const sendVerificationEmail = catchAsync(async (req, res) => {
  const { user } = req;
  if (user.isEmailVerified) {
    res.status(httpStatus.BAD_REQUEST).send('Email already verified');
  }
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(req.user);
  await emailService.sendVerificationEmail({ to: req.user.email, token: verifyEmailToken });
  res.status(httpStatus.NO_CONTENT).send();
});

export const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token as string);
  res.status(httpStatus.NO_CONTENT).send();
});

export const getMe = catchAsync(async (req, res) => {
  res.send(req.user);
});
