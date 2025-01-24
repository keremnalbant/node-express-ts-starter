import moment from 'moment';

import { config } from '../../config/config';
import { TokenType } from '../../config/tokens';
import * as tokenService from '../../services/token.service';

import { admin, userOne } from './user.fixture';

const accessTokenExpires = moment().add(config.jwt.accessExpirationMinutes, 'minutes');

export const userOneAccessToken = tokenService.generateToken({
  expires: accessTokenExpires,
  type: TokenType.ACCESS,
  userId: userOne._id.toString(),
});

export const adminAccessToken = tokenService.generateToken({
  expires: accessTokenExpires,
  type: TokenType.ACCESS,
  userId: admin._id.toString(),
});
