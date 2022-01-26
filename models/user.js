/** User class for message.ly */

const db = require('../db')
const bcrypt = require('bcrypt')
const { BCRYPT_WORK_FACTOR } = require("../config")
const ExpressError = require("../expressError")

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR)
    const current_time = new Date()
    const results = await db.query(
      `INSERT INTO users (
        username,
        password, 
        first_name,
        last_name,
        phone,
        join_at,
        last_login_at) 
        VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone]
    )
    return results.rows[0]
  }
  
  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    try {
      const results = await db.query(
        `SELECT password FROM users WHERE id=$1`,
        [username]
      )
      const user = results.rows[0]

      if (user) {
        if (await bcrypt.compare(password, user.password) === true) {
          return user && true
        }
      }
      throw new ExpressError("Invalid username/password", 400)
    } catch(err) {
      return next(err)
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const results = await db.query(
      `UPDATE users SET last_login_at=CURRENT_TIMESTAMP
      WHERE username=$1
      RETURNING username`,
      [username]
    )
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    try {
      const results = await db.query(
        `SELECT username, first_name, last_name, phone
        FROM users`
      )

      return results.rows
    } catch(err) {
      return next(err)
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    try {
      const results = await db.query(
        `SELECT username, first_name, last_name, phone
        FROM users WHERE username=$1`,
        [username]
      )

      if(!results.rows[0]) {
        throw new ExpressError(`User Not Found: ${username}`)
      }

      return results.rows[0]
    } catch(err) {
      return next(err)
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    try {
      const results = await db.query(
        `SELECT m.id, 
            m.to_user, 
            m.body, 
            m.sent_at, 
            m.read_at,
            u.first_name,
            u.last_name,
            u.phone
        FROM messages AS m
        JOIN users AS u
        ON m.to_user = u.username
        WHERE from_user=$1`,
        [username]
      )

      if(!results.rows[0]) {
        throw new ExpressError(`No Messages Found To ${username}`)
      }

      const messages = results.rows.map( row => ({
        id: row.id,
        to_user: {
          username: row.id,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone
        },
        body: row.body,
        sent_at: row.sent_at,
        read_at: row.read_at
      }))
  
      return messages
    } catch(err) {
      return next(err)
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    try {
      const results = await db.query(
        `SELECT 
            m.id, 
            m.to_user,
            m.body,
            m.sent_at,
            m.read_at
            u.first_name,
            u.last_name,
            u.phone
        FROM messages AS m
        JOIN users AS u
        ON m.to_user = u.username 
        WHERE to_user=$1`,
        [username]
      )

      if(!results.rows[0]) {
        throw new ExpressError(`No Messages Found To ${username}`)
      }
      
      const messages = results.rows.map( row => ({
        id: row.id,
        from_user: {
          username: row.from_user,
          first_name: row.first_name,
          last_name: row.last_name,
          phone: row.phone
        },
        body: row.body,
        sent_at: row.sent_at
      }))
      
      return messages
    } catch(err) {
      return next(err)
    }
  }
}

module.exports = User;