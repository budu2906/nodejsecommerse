const crypto = require('crypto')
const User = require('../models/user');
const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const sendGrid = require('nodemailer-sendgrid-transport')
const {validationResult} = require('express-validator')

const transporter = nodemailer.createTransport(sendGrid({
  auth: {
    api_key: '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',
     
  }
}))
exports.getLogin = (req, res, next) => {
  let message = req.flash('logError')
  if(message.length>0){
    message = message[0]
  }else{
    message = null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: ''
    },
    validationErrors: []
  });
};


exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  })
}


exports.getSignup = (req,res,next) =>{

  let message = req.flash('logError')
  if(message.length>0){
    message = message[0]
  }else{
    message = null
  }
  res.render('auth/signup',{
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
    errorMessage: message,
    oldInput:{
      email: "",
      password: "",
      confirmPassword: ""
    },
    validationErrors: []
  })
}

exports.postLogin = (req,res,next) =>{
  const email = req.body.email
  const password = req.body.password

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: 'Invalid email or password',
      validationErrors: [{param: 'email', param: 'password'}],
      oldInput: {
        email,password
      }
    });
  }


  User.findOne({email})
  .then(user=>{
    if(!user){
      return res.status(422).render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: 'Invalid email or password',
        oldInput: {
          email,password
        },
        validationErrors: [{param: 'email', param: 'password'}]
      });
    }
    bcrypt.compare(password, user.password)
    .then(doMatch=>{
      if(doMatch){
        req.session.isLoggedIn = true;
        req.session.user = user;
       return req.session.save(err=>{
          console.log(err)  
          return res.redirect('/')
        })
      
      }
      return res.status(422).render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: 'Invalid email or password',
        oldInput: {
          email,password
        },
        validationErrors: [{param: 'email', param: 'password'}]
      });
    })
    .catch(err=>{
      console.log(err)
      res.redirect('/login')
    })
   

  })
  .catch(err=>{
    const error = new Error(err)
    error.httpStatusCode = 500
    return next(error)
  })
}

exports.postSignup = (req,res,next)=>{
  const email = req.body.email
  const password = req.body.password
  const confirmPassword = req.body.confirmPassword
  const errors = validationResult(req)
  if(!errors.isEmpty()){
    console.log(errors.array())
    console.log(errors.array().find(e=>e.param==='email'))
    return res.status(422).render('auth/signup',{
      path: '/signup',
      pageTitle: 'Signup',
      isAuthenticated: false,
      errorMessage: errors.array()[0].msg,
      oldInput: {email,password, confirmPassword: req.body.confirmPassword},
      validationErrors: errors.array()
    })
  }
    bcrypt.hash(password, 12)
    .then(hashedPassword=>{
      const user = new User ({
        email,
        password: hashedPassword,
        cart : {items: []}
      })
      return user.save() 
    })
 

  .then(result=>{
    res.redirect('/login')
    return transporter.sendMail({
      to: email,
      from: 'chachibudu@gmail.com',
      subject: 'sign up succeded',
      html: '<h1>you successfully signed up </h1>'
    })
    .catch(err=>{
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
  })
}
exports.postLogout = (req,res,next)=>{
  req.session.destroy(err=>{
    console.log(err)
    res.redirect('/')
  })
}

exports.getReset =(req,res,next)=>{
  let message = req.flash('logError')
  if(message.length>0){
    message = message[0]
  }else{
    message = null
  }
  return res.render('auth/reset',{
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message,
  })
}


exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({ email: req.body.email })
      .then(user => {
        if (!user) {
          req.flash('error', 'No account with that email found.');
          return res.redirect('/reset');
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then(result => {
        res.redirect('/');
        transporter.sendMail({
          to: req.body.email,
          from: 'chachibudu@gmail.com',
          subject: 'Password reset',
          html: `
            <p>You requested a password reset</p>
            <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
          `
        });
      })
      .catch(err=>{
        const error = new Error(err)
        error.httpStatusCode = 500
        return next(error)
      })
  });
};



exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } })
    .then(user => {
      let message = req.flash('error');
      if (message.length > 0) {
        message = message[0];
      } else {
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
    .catch(err=>{
      const error = new Error(err)
      error.httpStatusCode = 500
      return next(error)
    })
};

exports.postNewPassword = (req,res,next)=>{
  const newPassword = req.body.password
  const userId = req.body.userId
  const passwordToken = req.body.passwordToken
  let resetUser;

  User.findOne({resetToken: passwordToken, resetTokenExpiration: {$gt: Date.now()}, _id:userId})
  .then(user=>{
    resetUser = user
    return bcrypt.hash(newPassword, 12)
    .then(hashedPassword=>{
       resetUser.password = hashedPassword
       resetUser.resetToken = null
       resetUser.resetTokenExpiration = undefined
       return user.save()
    })
    .then(result=>{
      res.redirect('/login')
    })
  })
  .catch(err=>{
    const error = new Error(err)
    error.httpStatusCode = 500
    return next(error)
  })
}