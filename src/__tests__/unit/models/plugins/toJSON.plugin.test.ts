import mongoose, { Connection, Schema } from 'mongoose';

import { toJSON } from '../../../../models/plugins';

describe('toJSON plugin', () => {
  let connection: Connection;

  beforeEach(() => {
    connection = mongoose.createConnection();
  });

  it('should replace _id with id', () => {
    const schema = new Schema();
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model();
    expect(doc.toJSON()).not.toHaveProperty('_id');
    expect(doc.toJSON()).toHaveProperty('id', doc._id.toString());
  });

  it('should remove __v', () => {
    const schema = new Schema();
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model();
    expect(doc.toJSON()).not.toHaveProperty('__v');
  });

  it('should remove createdAt and updatedAt', () => {
    const schema = new Schema({}, { timestamps: true });
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model();
    expect(doc.toJSON()).not.toHaveProperty('createdAt');
    expect(doc.toJSON()).not.toHaveProperty('updatedAt');
  });

  it('should remove any path set as private', () => {
    const schema = new Schema({
      private: { private: true, type: String },
      public: { type: String },
    });
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model({ private: 'some private value', public: 'some public value' });
    expect(doc.toJSON()).not.toHaveProperty('private');
    expect(doc.toJSON()).toHaveProperty('public');
  });

  it('should remove any nested paths set as private', () => {
    const schema = new Schema({
      nested: {
        private: { private: true, type: String },
      },
      public: { type: String },
    });
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model({
      nested: {
        private: 'some nested private value',
      },
      public: 'some public value',
    });
    expect(doc.toJSON()).not.toHaveProperty('nested.private');
    expect(doc.toJSON()).toHaveProperty('public');
  });

  it('should also call the schema toJSON transform function', () => {
    const schema = new Schema(
      {
        private: { type: String },
        public: { type: String },
      },
      {
        toJSON: {
          transform: (doc, ret) => {
            // eslint-disable-next-line no-param-reassign
            delete ret.private;
          },
        },
      },
    );
    schema.plugin(toJSON);
    const Model = connection.model('Model', schema);
    const doc = new Model({ private: 'some private value', public: 'some public value' });
    expect(doc.toJSON()).not.toHaveProperty('private');
    expect(doc.toJSON()).toHaveProperty('public');
  });
});
