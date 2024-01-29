
const express = require('express');

const {check,body} = require('express-validator')

const authController = require('../controllers/auth');

const router = express.Router();
const User = require('../models/user')

router.get('/login', authController.getLogin);

router.post('/login', authController.postLogin);
router.post('/logout', authController.postLogout)
router.get('/signup', authController.getSignup)
router.post('/signup', 
[
check('email')
.isEmail()
.withMessage('maili sheiyvane')
.normalizeEmail()
.custom((value,{req})=>{
    // if(value === 'test1234@gmail.com'){
    //     throw new Error('this email address is forbidden')
    // }
    // return true

    return User.findOne({email: value})
    .then(userDoc=>{
        if(userDoc){
           return Promise.reject('E-mail already exists, please, pick a different one')
        }
    })



}),
body('password', 'paroli siro')
.isLength({min: 6})
.isAlphanumeric()
.trim(),
body('confirmPassword').custom((value, {req})=>{
    if(value !== req.body.password){
        throw new Error('Passwords have to match -_-')

    }
    return true
})
.trim()
]
, authController.postSignup)
router.get('/reset', authController.getReset)
router.post('/reset', authController.postReset)
router.get('/reset/:token', authController.getNewPassword)
router.post('/new-password', authController.postNewPassword)

module.exports = router;