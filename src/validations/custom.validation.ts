import type { CustomValidator } from 'joi';

/* eslint-disable @typescript-eslint/no-explicit-any */
export const objectId: CustomValidator<string, any> = (value, helpers) => {
  if (!value.match(/^[0-9a-fA-F]{24}$/)) {
    return helpers.error('invalidId', {
      value,
    });
  }
  return value;
};

export const password: CustomValidator<string, any> = (value, helpers) => {
  if (value.length < 8 || !value.match(/\d/) || !value.match(/[a-zA-Z]/)) {
    return helpers.error('invalidPassword');
  }

  return value;
};
