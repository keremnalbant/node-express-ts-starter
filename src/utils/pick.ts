/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Create an object composed of the picked object properties
 */
export const pick = (object: { [key: string]: any }, keys: string[]) => {
  return keys.reduce((obj: { [key: string]: any }, key) => {
    if (object && Object.prototype.hasOwnProperty.call(object, key)) {
      // eslint-disable-next-line no-param-reassign
      obj[key] = object[key];
    }
    return obj;
  }, {});
};
