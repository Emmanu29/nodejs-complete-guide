const express = require('express');
const { check, body } = require('express-validator');

const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post('/login',
    [
        check('email')
            .isEmail()
            .withMessage('Please enter a valid Email')
            .normalizeEmail(),
        body('password')
            .isLength({ min: 5 })
            .withMessage('Please enter a password with at least 5 characters')
            .isAlphanumeric()
            .withMessage('Password should contain only numbers and text')
            .trim(),
    ],
    authController.postLogin);

router.post('/signup',
    [
        check('email')
        .isEmail()
        .withMessage('Please Enter A Valid Email')
        .custom((value, {req}) => {
        //    if(value === 'test@test.com'){
        //        throw new Error('This email address is forbidden');
        //    }
        //    return true;
        return User.findOne({email: value})
            .then(userDoc => {
                if(userDoc){
                    return Promise.reject("email already exist please try another one");
                }
            })
        })
        .normalizeEmail(),
        body(
            'password', 
            'Please enter a password with only numbers and text and atleast 5 characters')
            .isLength({ min: 5 })
            .isAlphanumeric()
            .trim(),
        body('confirmPassword')
        .trim()
        .custom((value, {req}) => {
            if(value !== req.body.password){
                throw new Error('Password have to match!')
            }
            return true;
        })
    ], 
     authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;