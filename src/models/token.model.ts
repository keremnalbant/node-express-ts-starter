import { Model, Schema, Types, model } from 'mongoose';

import { TokenType } from '../config/tokens';

import { toJSON } from './plugins';

export interface IToken {
  blacklisted: boolean;
  expires: Date;
  token: string;
  type: TokenType;
  user: string;
}

interface TokenModel extends Model<IToken> {}

const tokenSchema = new Schema(
  {
    blacklisted: {
      default: false,
      type: Boolean,
    },
    expires: {
      required: true,
      type: Date,
    },
    token: {
      index: true,
      required: true,
      type: String,
    },
    type: {
      enum: [TokenType.REFRESH, TokenType.RESET_PASSWORD, TokenType.VERIFY_EMAIL],
      required: true,
      type: String,
    },
    user: {
      ref: 'User',
      required: true,
      type: Types.ObjectId,
    },
  },
  {
    timestamps: true,
  },
);

// add plugin that converts mongoose to json
tokenSchema.plugin(toJSON);

export const Token = model<IToken, TokenModel>('Token', tokenSchema);
