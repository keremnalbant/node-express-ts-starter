import httpStatus from 'http-status';

import { TokenType } from '../config/tokens';
import { Token } from '../models/token.model';
import { ApiError } from '../utils/ApiError';

import * as tokenService from './token.service';
import * as userService from './user.service';

export const loginUserWithEmailAndPassword = async (email: string, password: string) => {
  const user = await userService.getUserByEmail(email);

  if (!user || !(await user.isPasswordMatch(password))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
  }
  return user;
};

export const logout = async (refreshToken: string) => {
  const refreshTokenDoc = await Token.findOne({ blacklisted: false, token: refreshToken, type: TokenType.REFRESH });
  if (!refreshTokenDoc) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
  }

  await refreshTokenDoc.deleteOne();
};

export const refreshAuth = async (refreshToken: string) => {
  try {
    const refreshTokenDoc = await tokenService.verifyToken({ token: refreshToken, type: TokenType.REFRESH });
    const user = await userService.getUserById(refreshTokenDoc.user);
    if (!user) {
      throw new Error();
    }

    await refreshTokenDoc.deleteOne();
    return await tokenService.generateAuthTokens(user);
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
  }
};

export const resetPassword = async ({
  newPassword,
  resetPasswordToken,
}: {
  resetPasswordToken: string;
  newPassword: string;
}) => {
  try {
    const resetPasswordTokenDoc = await tokenService.verifyToken({
      token: resetPasswordToken,
      type: TokenType.RESET_PASSWORD,
    });
    const user = await userService.getUserById(resetPasswordTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await userService.updateUserById(user.id, { password: newPassword });
    await Token.deleteMany({ type: TokenType.RESET_PASSWORD, user: user.id });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
  }
};

export const verifyEmail = async (verifyEmailToken: string) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken({ token: verifyEmailToken, type: TokenType.VERIFY_EMAIL });
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ type: TokenType.VERIFY_EMAIL, user: user.id });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};
