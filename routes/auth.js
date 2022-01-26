const User = require('../models/user')
const { SECRET_KEY } = require('../config')
const { Router } = require('express')
const router = new Router()
const jwt = require('jsonwebtoken')
const ExpressError = require('../expressError')

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async function(req, res, next) {
    try {
        if (await authenticate(req.body.username, req.body.password)) {
            const token = jwt.sign({username}, SECRET_KEY)
            User.updateLoginTimestamp(req.body.username)
            
            return res.json({token})
        } else {
            throw new ExpressError('Invalid username or password', 400)
        }
    } catch(err) {
        return next(err)
    }
})

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post('/register', async function(req, res, next) {
    try {
        const user = await User.register(req.body)
        const token = jwt.sign({username: user.username}, SECRET_KEY)
        User.updateLoginTimestamp(req.body.username)
        
        return res.json({token})
    } catch(err) {
        return next(err)
    }
})

module.exports = router