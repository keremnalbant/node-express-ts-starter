import type { Handler, NextFunction, Request, Response } from 'express';

export const catchAsync = (fn: Handler) => (req: Request, res: Response, next: NextFunction) => {
  Promise.resolve(fn(req, res, next)).catch((err) => next(err));
};
