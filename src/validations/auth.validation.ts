import Joi from 'joi';

import { password } from './custom.validation';

export const registerSchema = Joi.object({
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    password: Joi.string().required().custom(password).messages({
      invalidPassword: 'Password must be at least 8 characters long and contain at least 1 letter and 1 number.',
    }),
  }),
});

export const loginSchema = Joi.object({
  body: Joi.object().keys({
    email: Joi.string().required(),
    password: Joi.string().required(),
  }),
});

export const logoutSchema = Joi.object({
  body: Joi.object().keys({
    refreshToken: Joi.string().required(),
  }),
});

export const refreshTokensSchema = Joi.object({
  body: Joi.object().keys({
    refreshToken: Joi.string().required(),
  }),
});

export const forgotPasswordSchema = Joi.object({
  body: Joi.object().keys({
    email: Joi.string().email().required(),
  }),
});

export const resetPasswordSchema = Joi.object({
  body: Joi.object().keys({
    password: Joi.string().required().custom(password).messages({
      invalidPassword: 'Password must be at least 8 characters long and contain at least 1 letter and 1 number.',
    }),
  }),
  query: Joi.object().keys({
    token: Joi.string().required(),
  }),
});

export const verifyEmailSchema = Joi.object({
  query: Joi.object().keys({
    token: Joi.string().required(),
  }),
});
