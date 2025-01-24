import bcrypt from 'bcryptjs';
import { Schema, model, type PaginateModel, Document } from 'mongoose';
import validator from 'validator';

import { roles } from '../config/roles';

import { paginate, toJSON } from './plugins';

export interface IUser {
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  role: string;
  isEmailVerified: boolean;
}

export interface IUserMethods {
  isPasswordMatch(password: string): Promise<boolean>;
}

export interface IUserDocument extends IUser, Document, IUserMethods {
  id: string;
}

export interface IUserModel extends PaginateModel<IUserDocument> {
  isEmailTaken(email: string, excludeUserId?: string): Promise<boolean>;
}

const schema = new Schema<IUserDocument, IUserModel>(
  {
    email: {
      lowercase: true,
      required: true,
      trim: true,
      type: String,
      unique: true,
      validate(value: string) {
        if (!validator.isEmail(value)) {
          throw new Error('Invalid email');
        }
      },
    },
    firstName: {
      required: true,
      trim: true,
      type: String,
    },
    isEmailVerified: {
      default: false,
      type: Boolean,
    },
    lastName: {
      required: true,
      trim: true,
      type: String,
    },
    password: {
      minlength: 8,
      private: true, // used by the toJSON plugin
      required: false,
      trim: true,
      type: String,
      validate(value?: string) {
        if (value && (!value.match(/\d/) || !value.match(/[a-zA-Z]/))) {
          throw new Error('Password must contain at least one letter and one number');
        }
      },
    },
    role: {
      default: 'user',
      enum: roles,
      type: String,
    },
  },
  {
    timestamps: true,
  },
);

// add plugin that converts mongoose to json
schema.plugin(toJSON);
schema.plugin(paginate);

/**
 * Check if email is taken
 * @returns {Promise<boolean>}
 */
schema.static('isEmailTaken', async function (email, excludeUserId) {
  const user = await this.findOne({ _id: { $ne: excludeUserId }, email });
  return !!user;
});

/**
 * Check if password matches the user's password
 */
schema.method('isPasswordMatch', async function (this: IUserDocument, password: string) {
  return bcrypt.compare(password, this.password);
});

schema.pre<IUserDocument>('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 8);
  }
  next();
});

export const User = model<IUserDocument, IUserModel>('User', schema);
