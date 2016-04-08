require('./bootstrap') // Setup error handlers
// Add to the top of index.js
// Add to top of index.js with other requires
let crypto = require('crypto')
let SALT = 'CodePathHeartNodeJS'
require('songbird')

let LocalStrategy = require('passport-local').Strategy
let wrap = require('nodeifyit')
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let express = require('express')
let morgan = require('morgan')
const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000
let app = express()
let flash = require('connect-flash')
require('./user.js')

app.use(flash())

let mongoose = require('mongoose')
mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

let User = mongoose.model("User")

// Place the following just before app.use(express.static('public'))

app.use(cookieParser('ilovethenodejs')) // Session cookies
app.use(bodyParser.json()) // req.body for PUT/POST requests (login/signup)
app.use(bodyParser.urlencoded({ extended: true }))

// In-memory session support, required by passport.session()
app.use(session({
  secret: 'ilovethenodejs',
  resave: true,
  saveUninitialized: true
}))

app.use(passport.initialize()) // Enables passport middleware
app.use(passport.session()) // Enables passport persistent sessions

// Use ejs for templating, with the default directory /views
app.set('view engine', 'ejs')

// And add your root route after app.listen
// app.get('/', (req, res) => res.render('index.ejs', {}))
app.get('/', (req, res) => {
    res.render('index.ejs', {message: req.flash('error')})
})

// process the login form
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

// process the signup form
app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))


// let user = {
//     email: 'foo@foo.com',
//     password: crypto.pbkdf2Sync('asdf', SALT, 4096, 512, 'sha256').toString('hex')
// }

passport.use(new LocalStrategy({
    usernameField: 'email',
    failureFlash: true // Enables error messaging
}, wrap(async (email, password) => {
   let user = await User.promise.findOne({email})
   if (!user) {
       return [false, {message: 'Invalid email address'}]
   }
  let passwordHash = await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
   if (passwordHash.toString('hex') !== user.password) {
       return [false, {message: 'Invalid password'}]
   }
   return user
}, {spread: true})))  

passport.use('local-signup', new LocalStrategy({
   usernameField: 'email'
}, wrap(async (email, password) => {
    email = (email || '').toLowerCase()

    if (await User.promise.findOne({email})) {
        return [false, {message: 'That email is already taken.'}]
    }

    let user = new User()
    user.email = email

    // Store password as a hash instead of plain-text
    user.password = (await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
    return await user.save()
}, {spread: true})))

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect('/')
}
app.get('/profile', isLoggedIn, (req, res) => res.render('profile.ejs', {}))

// Use email since id doesn't exist
passport.serializeUser(wrap(async (user) => user.email))

passport.deserializeUser(wrap(async (email) => {
    return await User.findOne({email}).exec()
}))

// start server 
app.listen(PORT, ()=> console.log(`Listening @ http://127.0.0.1:${PORT}`))
