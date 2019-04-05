require("dotenv").config();
var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require("express-session");
var RedisStore = require('connect-redis')(session);
var redis = require("redis").createClient();
var bodyParser = require("body-parser");
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mysql = require('mysql');
var flash = require('connect-flash');
var methodOverride = require("method-override");
var bcrypt = require('bcryptjs');
var saltRounds = 10;
var indexRouter = require('./routes/index');
var cors = require('cors');
var app = express();

var connection = mysql.createConnection({
    host     : process.env.DB_HOSTNAME,
    user     : process.env.DB_USERNAME,
    password : process.env.DB_PASSWORD,
    port     : process.env.DB_PORT,
    database : process.env.DB_NAME,
    multipleStatements: true
});
connection.connect(function(err) {
    if (err) {
        console.error('error connecting: ' + err.stack);
        return;
    }
    console.log('connected as id ' + connection.threadId);
});
global.connection = connection;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(cors());
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(flash());
app.use(session({
    store: new RedisStore({ host: 'localhost', port: 6379, client: redis }),
    secret: "cats",
    resave: false,
    saveUninitialized: false
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(methodOverride('_method'));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
        usernameField: 'email',
        passReqToCallback : true // allows us to pass back the entire request to the callback
    },
    function(req, email, password, done) { // callback with email and password from our form
        connection.query("SELECT * FROM users WHERE email = (?)", [email], function(err, rows){
            console.log(rows);
            if (err) {
                return done(err);
            }
            if (!rows.length) {
                return done(null, false, req.flash('errors', 'No user found.'), req.flash('input', email));
            }
            // if the user is found but the password is wrong
            const hash = rows[0].password.toString();
            bcrypt.compare(password, hash, function(err, response) {
                if (response === true) {
                    return done(null, rows[0]);
                }
                return done(null, false, req.flash('errors', 'Oops! Wrong password.'), req.flash('input', email));
            });
            // if (!( rows[0].password === password))
            //     return done(null, false, req.flash('errors', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user

            // return done(null, rows[0]);

        });}
));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    connection.query("SELECT id, email, username, imageurl, level FROM users WHERE id = ?", [id], function(err,rows){
        done(err, rows[0]);
    });
});

app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
    next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
    // set locals, only providing error in development
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    // render the error page
    res.status(err.status || 500);
    // res.redirect('/404');
    res.render('404');
});

module.exports = app;
