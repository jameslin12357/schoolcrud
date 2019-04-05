var express = require('express');
var router = express.Router();
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var { body,validationResult } = require('express-validator/check');
var { sanitizeBody } = require('express-validator/filter');
var bcrypt = require('bcryptjs');
var saltRounds = 10;
var moment = require('moment');
var mysql = require('mysql');

// Middlewares
function isNotAuthenticated(req, res, next) {
    if (!(req.isAuthenticated())){
        return next();
    }
    res.redirect('/403');
}

function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}

// extract word after first slash and word after second slash
function isResource(req, res, next) {
    let uri = req._parsedOriginalUrl.path;
    if (uri.includes('/api')){
        uri = uri.substring(4);
    }
    if (uri.includes('?')){
        uri = uri.substring(0, uri.indexOf("?"));
    }
    uri = uri.substring(1);
    uri = uri.substring(0, uri.indexOf('/'));
    // let table = uri.substring(0, uri.length - 1);
    let table = uri;
    let id = Number(req.params.id);
    let connection = mysql.createConnection({
        host     : process.env.DB_HOSTNAME,
        user     : process.env.DB_USERNAME,
        password : process.env.DB_PASSWORD,
        port     : process.env.DB_PORT,
        database : process.env.DB_NAME,
        multipleStatements: true
    });
    connection.query('SELECT id FROM ' + table + ' WHERE id = ?', [id], function(error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        if (results.length === 0){
            res.render('404');
        }
        else {
            next();
        }
    });
}

// function isOwnResource(req, res, next) {
//     let uri = req._parsedOriginalUrl.path;
//     uri = uri.substring(1);
//     uri = uri.substring(0, uri.lastIndexOf('/'));
//     if (uri.includes('/')){
//         uri = uri.substring(0, uri.lastIndexOf('/'));
//     }
//     uri = uri.substring(0, uri.length - 1);
//     let table = uri;
//     let resourceid = req.params.id;
//     if (table === 'user') {
//         if (req.user.id !== Number(resourceid)) {
//             res.render('403');
//         } else {
//             next();
//         }
//     } else {
//         var connection = mysql.createConnection({
//             host     : process.env.DB_HOSTNAME,
//             user     : process.env.DB_USERNAME,
//             password : process.env.DB_PASSWORD,
//             port     : process.env.DB_PORT,
//             database : process.env.DB_NAME,
//             multipleStatements: true
//         });
//         connection.query('SELECT userid FROM ' + table + ' WHERE id = ?', [resourceid], function (error, results, fields) {
//             // error will be an Error if one occurred during the query
//             // results will contain the results of the query
//             // fields will contain information about the returned results fields (if any)
//             if (error) {
//                 throw error;
//             }
//             if (req.user.id !== results[0].userid) {
//                 res.render('403');
//             } else {
//                 next();
//             }
//         });
//     }
// }

/* GET home page. */
// if user is logged in return feed page else return home page
router.get('/', function(req, res, next) {
  if (req.isAuthenticated()) {
      connection.query('SELECT * FROM addresses ORDER BY date_created DESC; SELECT count(*) as count FROM addresses',
          function (error, results, fields) {
              if (error) {
                  throw error;
              }
              res.render('addresses/index', {
                  title: 'Addresses',
                  req: req,
                  results: results,
                  alert: req.flash('alert')
              });
          }
      );
  } else {
      res.redirect('/login');
  }
});

// USER ROUTES
router.get('/users/new', isNotAuthenticated, function(req, res, next){
    res.render('users/new', {
        title: 'Sign up',
        req: req,
        errors: req.flash('errors'),
        inputs: req.flash('inputs')
    });
});

// validate user input and if wrong redirect to register page with errors and inputs else save data into
// database and redirect to login with flash message
router.post('/users', isNotAuthenticated, [
    body('email', 'Empty email.').not().isEmpty(),
    body('password', 'Empty password.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('password', 'Password must be between 5-60 characters.').isLength({min:5, max:60}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail(),
    body('password', 'Password must contain one lowercase character, one uppercase character, a number, and ' +
        'a special character.').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i")
], function(req, res, next){
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username});
        res.redirect('/users/new');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('password').trim().escape();
        sanitizeBody('username').trim().escape();
        const email = req.body.email;
        const password = req.body.password;
        const username = req.body.username;
        bcrypt.hash(password, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            if (err) {
                throw error;
            }
            connection.query('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                [email, username, hash], function (error, results, fields) {
                    // error will be an Error if one occurred during the query
                    // results will contain the results of the query
                    // fields will contain information about the returned results fields (if any)
                    if (error) {
                        throw error;
                    }
                    req.flash('alert', 'You have successfully registered.');
                    res.redirect('/login');
                });
        });
    }
});

router.get('/users/:id', isResource, isAuthenticated, function(req, res){
    connection.query('SELECT id, email, username, description, imageurl, datecreated, level FROM users WHERE id = ?',
        [req.params.id],
        function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            console.log(results);
            res.render('users/show', {
                                title: 'Profile',
                                req: req,
                                results: results,
                                moment: moment,
                                alert: req.flash('alert')
                            });
        });
});

router.get('/users/:id/edit', isResource, isAuthenticated, function(req, res){
    if (req.user.id === Number(req.params.id)){
        connection.query('SELECT id, email, username, description FROM users WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('users/edit', {
                    title: 'Edit profile',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, [
    body('email', 'Empty email.').not().isEmpty(),
    body('username', 'Empty username.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200}),
    body('username', 'Username must be between 5-200 characters.').isLength({min:5, max:200}),
    body('description', 'Description must be between 5-200 characters.').isLength({min:5, max:200}),
    body('email', 'Invalid email.').isEmail()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        req.flash('errors', errors.array());
        req.flash('inputs', {email: req.body.email, username: req.body.username, description: req.body.description});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('email').trim().escape();
        sanitizeBody('username').trim().escape();
        sanitizeBody('description').trim().escape();
        const email = req.body.email;
        const username = req.body.username;
        const description = req.body.description;
        connection.query('UPDATE users SET email = ?, username = ?, description = ? WHERE id = ?',
            [email, username, description, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Profile edited.');
                res.redirect(req._parsedOriginalUrl.pathname);
            });
    }
});

router.delete('/users/:id', isResource, isAuthenticated, function(req, res, next){
    if (req.user.id === Number(req.params.id)){
        next();
    } else {
        res.render('403');
    }
}, function(req, res){
    connection.query('DELETE FROM users WHERE id = ?', [req.params.id], function (error, results, fields) {
        // error will be an Error if one occurred during the query
        // results will contain the results of the query
        // fields will contain information about the returned results fields (if any)
        if (error) {
            throw error;
        }
        req.flash('alert', 'Profile deleted.');
        req.logout();
        res.redirect('/');
    });
});


// address routes
router.get('/addresses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('addresses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/addresses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
},[
            body('building_number', 'Empty building number.').not().isEmpty(),
            body('street', 'Empty street.').not().isEmpty(),
            body('city', 'Empty city.').not().isEmpty(),
            body('state', 'Empty state.').not().isEmpty(),
            body('country', 'Empty country.').not().isEmpty(),
            body('zip', 'Empty zip.').not().isEmpty(),
            body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
            body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
            body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
            body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
            body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
            body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
        ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
                state: req.body.state, country: req.body.country, zip: req.body.zip});
            res.redirect('/addresses/new');
        }
        else {
            sanitizeBody('building_number').trim().escape();
            sanitizeBody('street').trim().escape();
            sanitizeBody('city').trim().escape();
            sanitizeBody('state').trim().escape();
            sanitizeBody('country').trim().escape();
            sanitizeBody('zip').trim().escape();
            const building_number = req.body.building_number;
            const street = req.body.street;
            const city = req.body.city;
            const state = req.body.state;
            const country = req.body.country;
            const zip = req.body.zip;
            connection.query('INSERT INTO addresses (building_number, street, city, state, country, zip) VALUES ' +
                '(?, ?, ?, ?, ?, ?)', [building_number, street, city, state, country, zip], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address created.');
                res.redirect('/');
            });
        }
    }
);

router.get('/addresses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, building_number, street, city, state, country, zip FROM addresses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('addresses/edit', {
                    title: 'Edit address',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
}, [
    body('building_number', 'Empty building number.').not().isEmpty(),
    body('street', 'Empty street.').not().isEmpty(),
    body('city', 'Empty city.').not().isEmpty(),
    body('state', 'Empty state.').not().isEmpty(),
    body('country', 'Empty country.').not().isEmpty(),
    body('zip', 'Empty zip.').not().isEmpty(),
    body('building_number', 'Building number must be between 5-100 characters.').isLength({min:5, max:100}),
    body('street', 'Street must be between 5-100 characters.').isLength({min:5, max:100}),
    body('city', 'City must be between 5-100 characters.').isLength({min:5, max:100}),
    body('state', 'State must be between 5-100 characters.').isLength({min:5, max:100}),
    body('country', 'Country must be between 5-100 characters.').isLength({min:5, max:100}),
    body('zip', 'Zip must be between 1-5 characters.').isLength({min:1, max:5}),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {building_number: req.body.building_number, street: req.body.street, city: req.body.city,
            state: req.body.state, country: req.body.country, zip: req.body.zip});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('building_number').trim().escape();
        sanitizeBody('street').trim().escape();
        sanitizeBody('city').trim().escape();
        sanitizeBody('state').trim().escape();
        sanitizeBody('country').trim().escape();
        sanitizeBody('zip').trim().escape();
        const building_number = req.body.building_number;
        const street = req.body.street;
        const city = req.body.city;
        const state = req.body.state;
        const country = req.body.country;
        const zip = req.body.zip;
        connection.query('UPDATE addresses SET building_number = ?, street = ?, city = ?, state = ?,' +
            'country = ?, zip = ? WHERE id = ?',
            [building_number, street, city, state, country, zip, req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address edited.');
                res.redirect('/');
            });
    }
});

router.delete('/addresses/:id', isResource, isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            connection.query('DELETE FROM addresses WHERE id = ?', [req.params.id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Address deleted.');
                res.redirect('/');
            });
        } else {
            res.render('403');
        }
        });

// attendance routes
router.get('/attendances', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM attendances ORDER BY date_created DESC; SELECT count(*) as count FROM attendances',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('attendances/index', {
                    title: 'Attendances',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/attendances/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('attendances/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/attendances', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('student_id', 'Empty student id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {student_id: req.body.student_id
                });
            res.redirect('/attendances/new');
        }
        else {
            sanitizeBody('student_id').trim().escape();
            const student_id = req.body.student_id;
            connection.query('INSERT INTO attendances (student_id) VALUES ' +
                '(?)', [student_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Attendance created.');
                res.redirect('/attendances');
            });
        }
    }
);

router.get('/attendances/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, student_id FROM attendances WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('attendances/edit', {
                    title: 'Edit attendance',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/attendances/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('student_id', 'Empty student id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {student_id: req.body.student_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('student_id').trim().escape();
        const student_id = req.body.student_id;
        connection.query('UPDATE attendances SET student_id = ? WHERE id = ?',
            [student_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Attendance edited.');
                res.redirect('/attendances');
            });
    }
});

router.delete('/attendances/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM attendances WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Attendance deleted.');
            res.redirect('/attendances');
        });
    } else {
        res.render('403');
    }
});

// course routes
router.get('/courses', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM courses ORDER BY date_created DESC; SELECT count(*) as count FROM courses',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('courses/index', {
                    title: 'Courses',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/courses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('courses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/courses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('section_id', 'Empty section id.').not().isEmpty(),
        body('department_id', 'Empty department id.').not().isEmpty(),
        body('room_id', 'Empty room id.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {title: req.body.title, description: req.body.description, section_id: req.body.section_id,
                department_id: req.body.department_id, room_id: req.body.room_id
            });
            res.redirect('/courses/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('section_id').trim().escape();
            sanitizeBody('department_id').trim().escape();
            sanitizeBody('room_id').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            const section_id = req.body.section_id;
            const department_id = req.body.department_id;
            const room_id = req.body.room_id;
            connection.query('INSERT INTO courses (name, description, section_id, department_id, room_id) VALUES ' +
                '(?, ?, ?,?, ?)', [name, description, section_id, department_id, room_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Course created.');
                res.redirect('/courses');
            });
        }
    }
);

router.get('/courses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description, section_id, department_id, room_id FROM courses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('courses/edit', {
                    title: 'Edit course',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/courses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('section_id', 'Empty section id.').not().isEmpty(),
    body('department_id', 'Empty department id.').not().isEmpty(),
    body('room_id', 'Empty room id.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {title: req.body.title, description: req.body.description, section_id: req.body.section_id,
            department_id: req.body.department_id, room_id: req.body.room_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('section_id').trim().escape();
        sanitizeBody('department_id').trim().escape();
        sanitizeBody('room_id').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        const section_id = req.body.section_id;
        const department_id = req.body.department_id;
        const room_id = req.body.room_id;
        connection.query('UPDATE courses SET name = ?, description = ?, section_id = ?, department_id = ?, room_id = ? WHERE id = ?',
            [name, description, section_id, department_id, room_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Course edited.');
                res.redirect('/courses');
            });
    }
});

router.delete('/courses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM courses WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Course deleted.');
            res.redirect('/courses');
        });
    } else {
        res.render('403');
    }
});

// department routes
router.get('/departments', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM departments ORDER BY date_created DESC; SELECT count(*) as count FROM departments',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('departments/index', {
                    title: 'Departments',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/departments/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('departments/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/departments', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('description', 'Empty description.').not().isEmpty(),
        body('teacher_id', 'Empty teacher id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, description: req.body.description, teacher_id: req.body.teacher_id
            });
            res.redirect('/departments/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('description').trim().escape();
            sanitizeBody('teacher_id').trim().escape();
            const name = req.body.name;
            const description = req.body.description;
            const teacher_id = req.body.teacher_id;
            connection.query('INSERT INTO departments (name, description, teacher_id) VALUES ' +
                '(?, ?, ?)', [name, description, teacher_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Department created.');
                res.redirect('/departments');
            });
        }
    }
);

router.get('/departments/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, description, teacher_id FROM departments WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('departments/edit', {
                    title: 'Edit department',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/departments/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('description', 'Empty description.').not().isEmpty(),
    body('teacher_id', 'Empty teacher id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, description: req.body.description, teacher_id: req.body.teacher_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('description').trim().escape();
        sanitizeBody('teacher_id').trim().escape();
        const name = req.body.name;
        const description = req.body.description;
        const teacher_id = req.body.teacher_id;
        connection.query('UPDATE departments SET name = ?, description = ?, teacher_id = ? WHERE id = ?',
            [name, description, teacher_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Department edited.');
                res.redirect('/departments');
            });
    }
});

router.delete('/departments/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM departments WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Department deleted.');
            res.redirect('/departments');
        });
    } else {
        res.render('403');
    }
});


// gender routes
router.get('/genders', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM genders ORDER BY date_created DESC; SELECT count(*) as count FROM genders',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('genders/index', {
                    title: 'Genders',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/genders/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('genders/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/genders', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('gender', 'Empty gender.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {gender: req.body.gender});
            res.redirect('/genders/new');
        }
        else {
            sanitizeBody('gender').trim().escape();
            const gender = req.body.gender;
            connection.query('INSERT INTO genders (gender) VALUES ' +
                '(?)', [gender], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender created.');
                res.redirect('/genders');
            });
        }
    }
);

router.get('/genders/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, gender FROM genders WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('genders/edit', {
                    title: 'Edit gender',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }
});

router.put('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('gender', 'Empty gender.').not().isEmpty(),
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {gender: req.body.gender});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('gender').trim().escape();
        const gender = req.body.gender;
        connection.query('UPDATE genders SET gender = ? WHERE id = ?',
            [gender, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Gender edited.');
                res.redirect('/genders');
            });
    }
});

router.delete('/genders/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM genders WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Gender deleted.');
            res.redirect('/genders');
        });
    } else {
        res.render('403');
    }
});

// category routes
router.get('/rooms', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM rooms ORDER BY date_created DESC; SELECT count(*) as count FROM rooms',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('rooms/index', {
                    title: 'Rooms',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/rooms/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('rooms/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/rooms', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('number', 'Empty number.').not().isEmpty(),
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {number: req.body.number
            });
            res.redirect('/rooms/new');
        }
        else {
            sanitizeBody('number').trim().escape();
            const number = req.body.number;
            connection.query('INSERT INTO rooms (number) VALUES ' +
                '(?)', [number], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Room created.');
                res.redirect('/rooms');
            });
        }
    }
);

router.get('/rooms/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, number FROM rooms WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('rooms/edit', {
                    title: 'Edit room',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/rooms/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('number', 'Empty number.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {number: req.body.number});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('number').trim().escape();
        const number = req.body.number;
        connection.query('UPDATE rooms SET number = ? WHERE id = ?',
            [number, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Room edited.');
                res.redirect('/rooms');
            });
    }
});

router.delete('/rooms/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM rooms WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Room deleted.');
            res.redirect('/rooms');
        });
    } else {
        res.render('403');
    }
});

// section routes
router.get('/sections', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM sections ORDER BY date_created DESC; SELECT count(*) as count FROM sections',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('sections/index', {
                    title: 'Sections',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/sections/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('sections/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/sections', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('name', 'Empty name.').not().isEmpty(),
        body('start', 'Empty start.').not().isEmpty(),
        body('end', 'Empty end.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {name: req.body.name, start: req.body.start, end: req.body.end});
            res.redirect('/sections/new');
        }
        else {
            sanitizeBody('name').trim().escape();
            sanitizeBody('start').trim().escape();
            sanitizeBody('end').trim().escape();
            const name = req.body.name;
            const start = req.body.start;
            const end = req.body.end;
            connection.query('INSERT INTO sections (name, start, end) VALUES ' +
                '(?, ?, ?)', [name, start, end], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Section created.');
                res.redirect('/sections');
            });
        }
    }
);

router.get('/sections/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, name, start, end FROM sections WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('sections/edit', {
                    title: 'Edit section',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/sections/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('name', 'Empty name.').not().isEmpty(),
    body('start', 'Empty start.').not().isEmpty(),
    body('end', 'Empty end.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {name: req.body.name, start: req.body.start, end: req.body.end});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('name').trim().escape();
        sanitizeBody('start').trim().escape();
        sanitizeBody('end').trim().escape();
        const name = req.body.name;
        const start = req.body.start;
        const end = req.body.end;
        connection.query('UPDATE sections SET name = ?, start = ?, end = ? WHERE id = ?',
            [name, start, end, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Section edited.');
                res.redirect('/sections');
            });
    }
});

router.delete('/sections/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM sections WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Section deleted.');
            res.redirect('/sections');
        });
    } else {
        res.render('403');
    }
});

// student routes
router.get('/students', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM students ORDER BY date_created DESC; SELECT count(*) as count FROM students',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('students/index', {
                    title: 'Students',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/students/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('students/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/students', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/students/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO students (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Student created.');
                res.redirect('/students');
            });
        }
    }
);

router.get('/students/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM students WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('students/edit', {
                    title: 'Edit student',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/students/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE students SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Student edited.');
                res.redirect('/students');
            });
    }
});

router.delete('/students/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM students WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Student deleted.');
            res.redirect('/students');
        });
    } else {
        res.render('403');
    }
});

// studentcourse routes
router.get('/studentscourses', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM studentscourses ORDER BY date_created DESC; SELECT count(*) as count FROM studentscourses',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('studentscourses/index', {
                    title: 'Studentscourses',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/studentscourses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('studentscourses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/studentscourses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('grade', 'Empty grade.').not().isEmpty(),
        body('student_id', 'Empty student id.').not().isEmpty(),
        body('course_id', 'Empty course id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {grade: req.body.grade, student_id: req.body.student_id, course_id: req.body.course_id});
            res.redirect('/studentscourses/new');
        }
        else {
            sanitizeBody('grade').trim().escape();
            sanitizeBody('student_id').trim().escape();
            sanitizeBody('course_id').trim().escape();
            const grade = req.body.grade;
            const student_id = req.body.student_id;
            const course_id = req.body.course_id;
            connection.query('INSERT INTO studentscourses (grade, student_id, course_id) VALUES ' +
                '(?, ?, ?)', [grade, student_id, course_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Studentcourse created.');
                res.redirect('/studentscourses');
            });
        }
    }
);

router.get('/studentscourses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, grade, student_id, course_id FROM studentscourses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('studentscourses/edit', {
                    title: 'Edit studentcourse',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/studentscourses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('grade', 'Empty grade.').not().isEmpty(),
    body('student_id', 'Empty student id.').not().isEmpty(),
    body('course_id', 'Empty course id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {grade: req.body.grade, student_id: req.body.student_id, course_id: req.body.course_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('grade').trim().escape();
        sanitizeBody('student_id').trim().escape();
        sanitizeBody('course_id').trim().escape();
        const grade = req.body.grade;
        const student_id = req.body.student_id;
        const course_id = req.body.course_id;
        connection.query('UPDATE studentscourses SET grade = ?, student_id = ?, course_id = ? WHERE id = ?',
            [grade, student_id, course_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Studentcourse edited.');
                res.redirect('/studentscourses');
            });
    }
});

router.delete('/studentscourses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM studentscourses WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Studentcourse deleted.');
            res.redirect('/studentscourses');
        });
    } else {
        res.render('403');
    }
});

// teacher routes
router.get('/teachers', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM teachers ORDER BY date_created DESC; SELECT count(*) as count FROM teachers',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('teachers/index', {
                    title: 'Teachers',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/teachers/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('teachers/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/teachers', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('first_name', 'Empty first name.').not().isEmpty(),
        body('last_name', 'Empty last name.').not().isEmpty(),
        body('age', 'Empty age.').not().isEmpty(),
        body('dob', 'Empty dob.').not().isEmpty(),
        body('email', 'Empty email.').not().isEmpty(),
        body('phone_number', 'Empty phone number.').not().isEmpty(),
        body('gender_id', 'Empty gender id.').not().isEmpty(),
        body('address_id', 'Empty address id.').not().isEmpty(),
        body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
        body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
                dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
                gender_id: req.body.gender_id, address_id: req.body.address_id});
            res.redirect('/teachers/new');
        }
        else {
            sanitizeBody('first_name').trim().escape();
            sanitizeBody('last_name').trim().escape();
            sanitizeBody('age').trim().escape();
            sanitizeBody('dob').trim().escape();
            sanitizeBody('email').trim().escape();
            sanitizeBody('phone_number').trim().escape();
            sanitizeBody('gender_id').trim().escape();
            sanitizeBody('address_id').trim().escape();
            const first_name = req.body.first_name;
            const last_name = req.body.last_name;
            const age = req.body.age;
            const dob = req.body.dob;
            const email = req.body.email;
            const phone_number = req.body.phone_number;
            const gender_id = req.body.gender_id;
            const address_id = req.body.address_id;
            connection.query('INSERT INTO teachers (first_name, last_name, age, dob, email, phone_number, gender_id, address_id) VALUES ' +
                '(?, ?, ?,?, ?, ?,?, ?)', [first_name, last_name, age, dob, email, phone_number, gender_id, address_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Teacher created.');
                res.redirect('/teachers');
            });
        }
    }
);

router.get('/teachers/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, first_name, last_name, age, dob, email, phone_number, gender_id, address_id FROM teachers WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('teachers/edit', {
                    title: 'Edit teacher',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/teachers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('first_name', 'Empty first name.').not().isEmpty(),
    body('last_name', 'Empty last name.').not().isEmpty(),
    body('age', 'Empty age.').not().isEmpty(),
    body('dob', 'Empty dob.').not().isEmpty(),
    body('email', 'Empty email.').not().isEmpty(),
    body('phone_number', 'Empty phone number.').not().isEmpty(),
    body('gender_id', 'Empty gender id.').not().isEmpty(),
    body('address_id', 'Empty address id.').not().isEmpty(),
    body('first_name', 'First Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('last_name', 'Last Name must be between 5-100 characters.').isLength({min:5, max:100}),
    body('email', 'Email must be between 5-200 characters.').isLength({min:5, max:200})
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {first_name: req.body.first_name, last_name: req.body.last_name, age: req.body.age,
            dob: req.body.dob, email: req.body.email, phone_number: req.body.phone_number,
            gender_id: req.body.gender_id, address_id: req.body.address_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('first_name').trim().escape();
        sanitizeBody('last_name').trim().escape();
        sanitizeBody('age').trim().escape();
        sanitizeBody('dob').trim().escape();
        sanitizeBody('email').trim().escape();
        sanitizeBody('phone_number').trim().escape();
        sanitizeBody('gender_id').trim().escape();
        sanitizeBody('address_id').trim().escape();
        const first_name = req.body.first_name;
        const last_name = req.body.last_name;
        const age = req.body.age;
        const dob = req.body.dob;
        const email = req.body.email;
        const phone_number = req.body.phone_number;
        const gender_id = req.body.gender_id;
        const address_id = req.body.address_id;
        connection.query('UPDATE teachers SET first_name = ?, last_name = ?, age = ?, dob = ?,' +
            'email = ?, phone_number = ?, gender_id = ?, address_id = ? WHERE id = ?',
            [first_name, last_name, age, dob, email, phone_number, gender_id, address_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Teacher edited.');
                res.redirect('/teachers');
            });
    }
});

router.delete('/teachers/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM teachers WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Teacher deleted.');
            res.redirect('/teachers');
        });
    } else {
        res.render('403');
    }
});

// teachercourse routes
router.get('/teacherscourses', function(req, res, next) {
    if (req.isAuthenticated()) {
        connection.query('SELECT * FROM teacherscourses ORDER BY date_created DESC; SELECT count(*) as count FROM teacherscourses',
            function (error, results, fields) {
                if (error) {
                    throw error;
                }
                res.render('teacherscourses/index', {
                    title: 'Teacherscourses',
                    req: req,
                    results: results,
                    alert: req.flash('alert')
                });
            }
        );
    } else {
        res.redirect('/login');
    }
});

router.get('/teacherscourses/new', isAuthenticated, function(req, res){
    if (req.user.level === 1){
        res.render('teacherscourses/new', {
            title: 'Create',
            req: req,
            errors: req.flash('errors'),
            inputs: req.flash('inputs')
        });
    } else {
        res.render('403');
    }
});

router.post('/teacherscourses', isAuthenticated, function(req, res, next) {
        if (req.user.level === 1){
            return next();
        } else {
            res.render('403');
        }
    },[
        body('teacher_id', 'Empty teacher id.').not().isEmpty(),
        body('course_id', 'Empty course id.').not().isEmpty()
    ]
    , (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            req.flash('errors', errors.array());
            req.flash('inputs', {teacher_id: req.body.teacher_id, course_id: req.body.course_id});
            res.redirect('/teacherscourses/new');
        }
        else {
            sanitizeBody('teacher_id').trim().escape();
            sanitizeBody('course_id').trim().escape();
            const teacher_id = req.body.teacher_id;
            const course_id = req.body.course_id;
            connection.query('INSERT INTO teacherscourses (teacher_id, course_id) VALUES ' +
                '(?, ?)', [teacher_id, course_id], function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Teachercourse created.');
                res.redirect('/teacherscourses');
            });
        }
    }
);

router.get('/teacherscourses/:id/edit', isResource, isAuthenticated, function(req, res) {
    if (req.user.level === 1){
        connection.query('SELECT id, teacher_id, course_id FROM teacherscourses WHERE id = ?', [req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                res.render('teacherscourses/edit', {
                    title: 'Edit teachercourse',
                    req: req,
                    results: results,
                    errors: req.flash('errors'),
                    inputs: req.flash('inputs')
                });
            });
    } else {
        res.render('403');
    }

});

router.put('/teacherscourses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        return next();
    } else {
        res.render('403');
    }
}, [
    body('teacher_id', 'Empty teacher id.').not().isEmpty(),
    body('course_id', 'Empty course id.').not().isEmpty()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // There are errors. Render form again with sanitized values/errors messages.
        // Error messages can be returned in an array using `errors.array()`.
        req.flash('errors', errors.array());
        req.flash('inputs', {teacher_id: req.body.teacher_id, course_id: req.body.course_id});
        res.redirect(req._parsedOriginalUrl.pathname + '/edit');
    }
    else {
        sanitizeBody('teacher_id').trim().escape();
        sanitizeBody('course_id').trim().escape();
        const teacher_id = req.body.teacher_id;
        const course_id = req.body.course_id;
        connection.query('UPDATE teacherscourses SET teacher_id = ?, course_id = ? WHERE id = ?',
            [teacher_id, course_id, req.params.id],
            function (error, results, fields) {
                // error will be an Error if one occurred during the query
                // results will contain the results of the query
                // fields will contain information about the returned results fields (if any)
                if (error) {
                    throw error;
                }
                req.flash('alert', 'Teachercourse edited.');
                res.redirect('/teacherscourses');
            });
    }
});

router.delete('/teacherscourses/:id', isResource, isAuthenticated, function(req, res, next) {
    if (req.user.level === 1){
        connection.query('DELETE FROM teacherscourses WHERE id = ?', [req.params.id], function (error, results, fields) {
            // error will be an Error if one occurred during the query
            // results will contain the results of the query
            // fields will contain information about the returned results fields (if any)
            if (error) {
                throw error;
            }
            req.flash('alert', 'Teachercourse deleted.');
            res.redirect('/teacherscourses');
        });
    } else {
        res.render('403');
    }
});

router.get('/login', isNotAuthenticated, function(req, res, next){
    res.render('login', {
        title: 'Log in',
        req: req,
        errors: req.flash('errors'),
        input: req.flash('input'),
        alert: req.flash('alert')
    });
});

router.post('/login', isNotAuthenticated, passport.authenticate('local', {
        successRedirect: '/',
        failureRedirect: '/login',
        failureFlash: true
    })
);

router.get('/logout', isAuthenticated, function(req, res){
    req.logout();
    res.redirect('/login');
});

module.exports = router;
