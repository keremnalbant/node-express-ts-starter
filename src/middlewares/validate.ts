import type { Handler } from 'express';
import httpStatus from 'http-status';
import { type Schema } from 'joi';

import { ApiError } from '../utils/ApiError';
import { pick } from '../utils/pick';

export const validate =
  (schema: Schema): Handler =>
  (req, res, next) => {
    const validSchema = pick(schema.describe().keys, ['params', 'query', 'body']);
    const object = pick(req, Object.keys(validSchema));
    const { error, value } = schema.validate(object);

    if (error) {
      const errorMessage = error.details.map((details) => details.message).join(', ');
      return next(new ApiError(httpStatus.BAD_REQUEST, errorMessage));
    }
    Object.assign(req, value);
    return next();
  };
