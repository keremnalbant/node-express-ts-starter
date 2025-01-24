import type { IUserDocument } from '../models';

declare global {
  namespace Express {
    interface User extends IUserDocument {}
  }
}

declare module 'http' {
  interface IncomingMessage {
    user: IUserDocument;
  }
}
