import Joi from 'joi';

import { password, objectId } from './custom.validation';

export const createUserSchema = Joi.object({
  body: Joi.object().keys({
    email: Joi.string().required().email(),
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    password: Joi.string().required().custom(password).messages({
      invalidPassword: 'Password must be at least 8 characters long and contain at least 1 letter and 1 number.',
    }),
    role: Joi.string().required().valid('user', 'admin'),
  }),
});

export const getUsersSchema = Joi.object({
  query: Joi.object().keys({
    firstName: Joi.string(),
    lastName: Joi.string(),
    limit: Joi.number().integer(),
    page: Joi.number().integer(),
    role: Joi.string(),
    sortBy: Joi.string(),
  }),
});

export const getUserSchema = Joi.object({
  params: Joi.object().keys({
    userId: Joi.string().custom(objectId).messages({
      invalidId: "User ID: '{{#value}}' is not a valid id.",
    }),
  }),
});

export const updateUserSchema = Joi.object({
  body: Joi.object()
    .keys({
      email: Joi.string().email(),
      firstName: Joi.string(),
      lastName: Joi.string(),
      password: Joi.string().custom(password).messages({
        invalidPassword: 'Password must be at least 8 characters long and contain at least 1 letter and 1 number.',
      }),
    })
    .min(1),
  params: Joi.object().keys({
    userId: Joi.string().custom(objectId).messages({
      invalidId: "User ID: '{{#value}}' is not a valid id.",
    }),
  }),
});

export const deleteUserSchema = Joi.object({
  params: Joi.object().keys({
    userId: Joi.string().custom(objectId).messages({
      invalidId: "User ID: '{{#value}}' is not a valid id.",
    }),
  }),
});
