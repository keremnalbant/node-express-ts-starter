import passport from 'passport';
import { ExtractJwt, Strategy as JwtStrategy, StrategyOptionsWithoutRequest, type VerifiedCallback } from 'passport-jwt';

import { IUserDocument, User } from '../models';

import { config } from './config';
import { TokenType } from './tokens';

const jwtOptions: StrategyOptionsWithoutRequest = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: config.jwt.secret,
};

const jwtVerify = async (payload: { exp: number; iat: number; type: TokenType; sub: string }, done: VerifiedCallback) => {
  try {
    if (payload.type !== TokenType.ACCESS) {
      throw new Error('Invalid token type');
    }
    const user = await User.findById(payload.sub);
    if (!user) {
      return done(null, false);
    }
    done(null, user.toJSON());
  } catch (error) {
    done(error, false);
  }
};

export const jwtStrategy = new JwtStrategy(jwtOptions, jwtVerify);

passport.serializeUser(function (user: IUserDocument, done) {
  done(null, user);
});

passport.deserializeUser(function (user: IUserDocument, done) {
  done(null, user);
});
