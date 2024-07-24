const crypto = require('crypto');

const User = require('../models/user');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');



// Create a transporter object
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // use SSL
  auth: {
    user: 'palasigue.emmanuel25@gmail.com',
    pass: 'rkad mwhh vyuv bjzd',
  }
});


exports.getLogin = (req, res, next) => {
    let message = req.flash('error');
    if(message.length > 0){
        message = message[0];
    }else {
        message = null;
    }

    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: message,
        oldInput: { 
            email: "", 
            password: '',
          },
        validationErrors: []
    });
};

exports.getSignup = (req, res, next) => {
    let message = req.flash('error');
    if(message.length > 0){
        message = message[0];
    }else {
        message = null;
    }

    res.render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: message,
      oldInput: { 
        email: "", 
        password: '', 
        confirmPassword: ''
      },
      validationErrors: []
    });
  };

exports.postLogin = (req, res, next) => {
    const email      = req.body.email;
    const password   = req.body.password;

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email: email,
                password: password
            },
            validationErrors: errors.array()
        });
    }

    User.findOne({email: email})
    .then(user => {
        if(!user){
            return res.status(422).render('auth/login', {
                path: '/login',
                pageTitle: 'Login',
                errorMessage: 'Invalid email or password',
                oldInput: {
                    email: email,
                    password: password
                },
                validationErrors: []
            });
        }

        bcrypt.compare(password, user.password)
        .then(doMatch => {
            if(doMatch){
                req.session.isLoggedIn   = true;
                req.session.user         = user;

                return req.session.save(err => {
                    console.log(err);
                    req.flash('success', 'Successfully Login');
                    res.redirect('/');
                });    
            }
            return res.status(422).render('auth/login', {
                path: '/login',
                pageTitle: 'Login',
                errorMessage: 'Invalid email or password',
                oldInput: {
                    email: email,
                    password: password
                },
                validationErrors: []
            });
        })
        .catch(err => {
            console.log(err);
            res.redirect('/login')
        });  
    })
    .catch(err => {
        console.log(err)
    });
};

exports.postSignup = (req, res, next) => {
    const email              = req.body.email;
    const password           = req.body.password;

    const errors = validationResult(req);
    if(!errors.isEmpty()){
        console.log(errors.array());
        return res.status(422)
        .render('auth/signup', {
            path: '/signup',
            pageTitle: 'Signup',
            errorMessage: errors.array()[0].msg,
            oldInput: { 
                email: email, 
                password: password, 
                confirmPassword: req.body.confirmPassword 
            },
            validationErrors: errors.array()
          });
        }
        bcrypt
        .hash(password, 12)
        .then(hashPassword => {
            const user = new User({
                email:       email,
                password:    hashPassword,
                cart:        { items: []}
            });
            return user.save();
        })
        .then(result => {
            res.redirect('/login')
            return transporter.sendMail({
                from: '"Shoppee" <palasigue.emmanuel25@gmail.com>', 
                to: email, 
                subject: "Signup succeeded", // Subject line
                text: 'That was easy!',
                html: "<b>Hello world?</b>", // html body
            })
        .catch(err => {
            console.log(err);
        });
    });
};

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err);
        res.redirect('/');
    });
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
    if(message.length > 0){
        message = message[0];
    }else {
        message = null;
    }

  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset',
    errorMessage: message
  });
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if(err){
            console.log(err);
            return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User.findOne({email: req.body.email})
        .then(user => {
            if(!user){
                req.flash('error', 'No account with that emaiil found');
                return res.redirect('/reset');
            }
            user.resetToken = token;
            user.resetTokenExpiration = Date.now() + 3600000;
            return user.save();
        })
        .then(result => {
            res.redirect('/');
            transporter.sendMail({
                from: '"Shoppee" <palasigue.emmanuel25@gmail.com>', 
                to: req.body.email, 
                subject: "Password Reset", // Subject line
                text: 'That was easy!',
                html: `
                    <p>You requested a password reset</p>
                    <p>Click this <a href = "http://localhost:3000/reset/${token}">Link</a> to set a new password </p>
                ` 
            });
        })
        .catch(err => {z
            console.log(err);
        });
    });
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;

    User.findOne({
        resetToken: token, resetTokenExpiration: {$gt: Date.now()}
    })
    .then(user => {
        let message = req.flash('error');
        if(message.length > 0){
            message = message[0];
        }else {
            message = null;
        }

        res.render('auth/new-password', {
            path: '/new-password',
            pageTitle: 'New Password',
            errorMessage: message,
            userId: user._id.toString(),
            passwordToken: token
        });
    })
    .catch(err => {
        console.log(err);
    });

    
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password;
    const userId = req.body.userId;
    const passwordToken = req.body.passwordToken;
    let resetUser;

    User.findOne({
        resetToken: passwordToken,
        resetTokenExpiration: {$gt: Date.now()},
        _id: userId
    })
    .then(user => {
        resetUser = user;
        return bcrypt.hash(newPassword, 12);
    })
    .then(hashedPassword => {
        resetUser.password = hashedPassword;
        resetUser.resetToken = undefined;
        resetUser.resetTokenExpiration = undefined;
        return resetUser.save();
    })
    .then(result => {
        req.flash('success', 'Password Successfully Reset');
        res.redirect('/login');
    })
    .catch(err => {
        console.log(err);
    });


}
