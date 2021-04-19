// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router();
const bcrypt = require('bcryptjs');
const helpers = require('../users/users-model.js')

router.post('/register', (req, res, next) => {
  const { username, password } = req.body
  
  const hash = bcrypt.hashSync(password, 12)

  helpers.add({ username, password: hash })
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 201
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', async (req,res,next) => {
  const { username, password } = req.body

  const [user] = await helpers.findBy({ username })

  if(user && bcrypt.compareSync(password, user.password)) {
    req.body.session.user = user
    res.status(200).json({ message: `Welcome ${username}!`})
  } else {
    next({ status: 401, message: `Invalid credentials` })
  }
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */



  router.get('/logout', (req,res,next) => {
    if (req.session && req.session.user) {
      req.session.destroy(err => {
        if (err) {
          next({ status:200, message: `sorry, you can not leave` })
        } else {
          res.status(200).json({ message:`logged out`})
        }
      })
    } else {
      next({ status: 200, message: `no session`})
    }
  })

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;