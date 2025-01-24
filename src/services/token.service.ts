import httpStatus from 'http-status';
import jwt from 'jsonwebtoken';
import moment, { type Moment } from 'moment';

import { config } from '../config/config';
import { TokenType } from '../config/tokens';
import { Token, type IUserDocument } from '../models';
import { ApiError } from '../utils/ApiError';

import * as userService from './user.service';

export const generateToken = ({
  expires,
  secret = config.jwt.secret,
  type,
  userId,
}: {
  userId: string;
  expires: Moment;
  type: TokenType;
  secret?: string;
}) => {
  const payload = {
    exp: expires.unix(),
    iat: moment().unix(),
    sub: userId,
    type,
  };
  return jwt.sign(payload, secret);
};

export const saveToken = async ({
  blacklisted = false,
  expires,
  token,
  type,
  userId,
}: {
  token: string;
  userId: string;
  expires: Moment;
  type: TokenType;
  blacklisted?: boolean;
}) => {
  const tokenDoc = await Token.create({
    blacklisted,
    expires: expires.toDate(),
    token,
    type,
    user: userId,
  });
  return tokenDoc;
};

export const verifyToken = async ({ token, type }: { token: string; type: string }) => {
  const payload = jwt.verify(token, config.jwt.secret);
  const tokenDoc = await Token.findOne({ blacklisted: false, token, type, user: payload.sub });
  if (!tokenDoc) {
    throw new Error('Token not found');
  }
  return tokenDoc;
};

export const generateAuthTokens = async (user: IUserDocument) => {
  const accessTokenExpires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');
  const accessToken = generateToken({
    expires: accessTokenExpires,
    type: TokenType.ACCESS,
    userId: user.id,
  });

  const refreshTokenExpires = moment().add(config.jwt.refreshExpirationDays, 'days');
  const refreshToken = generateToken({
    expires: refreshTokenExpires,
    type: TokenType.REFRESH,
    userId: user.id,
  });

  await saveToken({ expires: refreshTokenExpires, token: refreshToken, type: TokenType.REFRESH, userId: user.id });

  return {
    access: {
      expires: accessTokenExpires.toDate(),
      token: accessToken,
    },
    refresh: {
      expires: refreshTokenExpires.toDate(),
      token: refreshToken,
    },
  };
};

export const generateResetPasswordToken = async (email: string) => {
  const user = await userService.getUserByEmail(email);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'No users found with this email');
  }
  const expires = moment().add(config.jwt.resetPasswordExpirationMinutes, 'minutes');
  const resetPasswordToken = generateToken({ expires, type: TokenType.RESET_PASSWORD, userId: user.id });
  await saveToken({ expires, token: resetPasswordToken, type: TokenType.RESET_PASSWORD, userId: user.id });
  return resetPasswordToken;
};

export const generateVerifyEmailToken = async (user: IUserDocument) => {
  const expires = moment().add(config.jwt.verifyEmailExpirationMinutes, 'minutes');
  const verifyEmailToken = generateToken({ expires, type: TokenType.VERIFY_EMAIL, userId: user.id });
  await saveToken({ expires, token: verifyEmailToken, type: TokenType.VERIFY_EMAIL, userId: user.id });
  return verifyEmailToken;
};
