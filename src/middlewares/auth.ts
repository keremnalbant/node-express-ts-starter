import type { Request, Response, NextFunction } from 'express';
import httpStatus from 'http-status';
import passport from 'passport';

import { roleRights } from '../config/roles';
import type { IUserDocument } from '../models';
import { ApiError } from '../utils/ApiError';

const verifyCallback =
  (req: Request, resolve: (reason?: unknown) => void, reject: (reason?: unknown) => void, requiredRights: string[]) =>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async (err: any, user: IUserDocument, info: any) => {
    if (err || info || !user) {
      return reject(new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate'));
    }
    req.user = user;

    if (requiredRights.length) {
      const userRights = roleRights.get(user.role);
      const hasRequiredRights = requiredRights.every((requiredRight) => userRights.includes(requiredRight));
      if (!hasRequiredRights && req.params.userId !== user.id) {
        return reject(new ApiError(httpStatus.FORBIDDEN, 'Forbidden'));
      }
    }

    resolve();
  };

export const auth =
  (...requiredRights: string[]) =>
  async (req: Request, res: Response, next: NextFunction) => {
    return new Promise((resolve, reject) => {
      passport.authenticate('jwt', verifyCallback(req, resolve, reject, requiredRights))(req, res, next);
    })
      .then(() => next())
      .catch((err) => {
        next(err);
      });
  };
