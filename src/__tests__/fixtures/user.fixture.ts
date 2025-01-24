import { faker } from '@faker-js/faker';
import bcrypt from 'bcryptjs';
import { Types } from 'mongoose';

import { User, type IUser } from '../../models/user.model';

const password = 'password1';
const salt = bcrypt.genSaltSync(8);
const hashedPassword = bcrypt.hashSync(password, salt);

export const userOne: IUser & { _id: string } = {
  _id: new Types.ObjectId().toString(),
  email: faker.internet.email().toLowerCase(),
  firstName: faker.person.firstName(),
  isEmailVerified: false,
  lastName: faker.person.lastName(),
  password,
  role: 'user',
};

export const userTwo: IUser & { _id: string } = {
  _id: new Types.ObjectId().toString(),
  email: faker.internet.email().toLowerCase(),
  firstName: faker.person.firstName(),
  isEmailVerified: false,
  lastName: faker.person.lastName(),
  password,
  role: 'user',
};

export const admin: IUser & { _id: string } = {
  _id: new Types.ObjectId().toString(),
  email: faker.internet.email().toLowerCase(),
  firstName: faker.person.firstName(),
  isEmailVerified: false,
  lastName: faker.person.lastName(),
  password,
  role: 'admin',
};

export const insertUsers = async (users: IUser[]) => {
  await User.insertMany(users.map((user) => ({ ...user, password: hashedPassword })));
};
