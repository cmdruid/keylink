/** store.js
 * Class object for managing a persistent storage space.
 **/

/** [ CONFIGS ] ==================================== */

const dataDir = 'data';

/** [ IMPORTS ] ==================================== */

import path from 'path';
import { LocalStorage } from 'node-localstorage'

/** [ EXPORTS ] ==================================== */

export default class Store {

  static create(pathStr) {
    // Create the local store in the specified path.
    const relpath    = pathStr.split('/'),
          filename   = relpath.pop(),
          fullpath   = path.join(process.cwd(), dataDir, ...relpath),
          localstore = (typeof window !== 'undefined')
            ? window.localStorage
            : new LocalStorage(fullpath)

    return {
      name: filename,
      store: localstore,
      data: Store.parse(localstore, filename)
    }
  }

  static parse(localstore, filename) {
    // Parse stored string into a map object, or return new map.
    const rawString = localstore.getItem(filename),
          cachedMap = (rawString)
            ? JSON.parse(rawString, Store.decode)
            : new Map();
    return (Store.test(cachedMap))
      ? cachedMap
      : new Map();
  }

  static test(map) {
    // Test if map object is valid.
    if (!map) throw new Error('Map undefined!');
    try {
      const testKey = Math.random();
      map.set('test', testKey);
      return (map.get('test') === testKey)
        ? map.delete('test')
        : false;
    } catch(err) { console.error(err) }
  }

  static encode(key, value) {
    // Convert non-standard javascript objects to json.
    if (value instanceof Map)
      return { type: 'Map', value: [ ...value ] };
    if (value instanceof Date)
      return { type: 'Date', value: value };
    return value;
  }

  static decode(key, value) {
    // Convert non-standard json objects to javascript.
    if (typeof value === 'object' && value !== null) {
      if (value.type === 'Map') return new Map(value.value);
      if (value.type === 'Date') return new Date(value.value);
    }
    return value;
  }

  constructor(pathStr) {
    const { name, data, store } = Store.create(pathStr);
    this.name  = name;
    this.data  = data;
    this.size  = data.size;
    this.store = store;
    return this;
  }

  _commit() {
    // Save any changes in map object to disk.
    try {
      let rawString = JSON.stringify(this.data, Store.encode);
      this.store.setItem(this.name, rawString);
      return true;
    } catch(err) { console.error(err) }
  }

  getItem(key) {
    return this.get(key)
  }

  setItem(key, val) {
    let res = this.set(key, val);
    if (res) this._commit();
    return res;
  }

  delete(key) {
    let res = this.data.delete(key);
    if (res) this._commit();
    return res;
  }

  clear() {
    try {
      return this.store.clear();
    } catch(err) { console.error(err) }
  }

  entries() {
    return this.data.entries();
  }

  keys() {
    return this.data.keys();
  }

  values() {
    return this.data.values();
  }

  has(key) {
    return this.data.has(key);
  }

  toString() {
    return JSON.stringify(this.data, Store.encode, 2);
  }

  [Symbol.iterator]() {
    return this.data[Symbol.iterator]();
  }
}
