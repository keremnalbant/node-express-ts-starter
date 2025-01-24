import mongoose from 'mongoose';

import { config } from '../config/config';

const cleanDatabase = async () => {
  const { collections } = mongoose.connection;
  await Promise.all(Object.keys(collections).map((collection) => collections[collection].deleteMany({})));
};

beforeAll(async () => {
  await mongoose.connect(config.mongoose.url);
  // eslint-disable-next-line no-console
  console.log('Connected to MongoDB');
});

beforeEach(async () => {
  await cleanDatabase();
});

afterAll(async () => {
  await cleanDatabase();
  await mongoose.disconnect();
  // eslint-disable-next-line no-console
  console.log('Disconnected from MongoDB');
});
