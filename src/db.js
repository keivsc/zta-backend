import Logger from './logging.js';
import sqlite3 from 'sqlite3';

const logger = new Logger('db');

const sqlite = new sqlite3.verbose();

class Database {
  constructor(name) {
    this.db = new sqlite.Database(`./database/${name}`, (err) => {
      if (err) {
        logger.error(`Could not connect to database [${name}]`, err);
      } else {
        logger.info(`Connected to SQLite database [${name}]`);
      }
    });
  }

async get(sql, params = [], options = {}) {
  const { mapFn = (row) => row, returnEmptyObj = false } = options;

  return new Promise((resolve, reject) => {
    this.db.get(sql, params, (err, row) => {
      if (err) {
        logger.error('DB get error', err);
        reject(err);
      } else {
        if (!row) {
          resolve(returnEmptyObj ? {} : null);
        } else {
          resolve(mapFn(row));
        }
      }
    });
  });
}


  // Promise-based multiple rows query
  async getAll(sql, params = [], mapFn = (row) => row) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          logger.error('DB getAll error', err);
          reject(err);
        } else {
          resolve(rows.map(mapFn));
        }
      });
    });
  }

  // Promise-based run for INSERT, UPDATE, DELETE
  async run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) {
          logger.error('DB run error: ', err);
          reject(err);
        } else {
          resolve(this); // return the statement object
        }
      });
    });
  }

}

export default Database;