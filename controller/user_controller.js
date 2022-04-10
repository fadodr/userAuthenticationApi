const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../model/user')
const _ = require('lodash')
const RefreshToken = require('../model/tokens')

const mailgun = require("mailgun-js");
const mg = mailgun({apiKey: process.env.API_KEY, domain: process.env.DOMAIN});


exports.signup_user = async (req, res, next) => {

    const { name, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(401).send('Email already exist')
        }
        const hashpwd = await bcrypt.hash(password, 10);
        const token = jwt.sign({ name: name, email: email, password: hashpwd }, process.env.JWT_SECRET_KEY, {expiresIn : '15m'});
        
        const data = {
            from: 'noreply@gmail.com',
            to: email,
            subject: 'Email Verification',
            text: 'please verify your email with so so so token ' + token
        };

        mg.messages().send(data, function (error, body) {
            if (!error) {
                return res.status(200).json({
                    message : 'Email confirmation link sent to the specified email'
                })
            }
            else {
                return res.status(400).send(error.message)
            }
        });
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}

exports.activate_user = async (req, res, next) => {
    const { token } = req.body
    try {
        const { name, email, password } = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const user = new User({
            name, email, password
        });
        await user.save();
        res.status(201).send(user); 
    }
    catch (error) {
        return res.status(500).send(error.message);
    }
}

exports.login_user = async (req, res, next) => {
    const { email, password } = req.body
    
    try {
        const existingUser = await User.findOne({ email })
        if (!existingUser) {
            return res.status(200).send('Incorrect email or password')
        }
        const isCorrect = await await bcrypt.compare(password, existingUser.password)
        if (!isCorrect) {
            return res.status(200).send('Incorrect email or password')
        }

        const accessToken = jwt.sign({ id: existingUser._id, email: existingUser.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' })
        const refreshToken = jwt.sign({ id: existingUser._id, email: existingUser.email }, process.env.JWT_REFRESH_SECRET, {expiresIn: '1d'})

        const response = await RefreshToken.findOneAndUpdate({ userId : existingUser._id }, { $push: { tokens: refreshToken } })
        if (response == null) {
            const newRefreshToken = new RefreshToken({
                userId: existingUser._id,
                tokens: [refreshToken]
            })
            await newRefreshToken.save()
        }
        res.status(200).json({
            tokenData: {
                accessToken: accessToken,
                accessTokenExpiresIn: new Date(Date.now() + 4500000).toISOString(),
                refreshToken : refreshToken
            },
            user : existingUser
        })
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}

exports.refresh_token = async (req, res, next) => {
    const refreshToken  = req.body.token

    try {
        if (refreshToken == null) return res.sendStatus(401)
        const refreshTokenData = await RefreshToken.findOne({ userId: req.body.userId })
        if (!refreshTokenData['tokens'].includes(refreshToken)) {
            return res.status(403).send('Invalid token')
        }
        const existingUser = await User.findById(req.body.userId)
        jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err, user) => {
            if (err)  return res.status(403).send('Invalid token')
            const accessToken = jwt.sign({ id: existingUser._id, email: existingUser.email }, process.env.JWT_ACCESS_SECRET, { expiresIn: '15m' })
            res.status(200).json({
                accessToken: accessToken,
                accessTokenExpiresIn: new Date(Date.now() + 4500000).toISOString(),
            })
        })
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}

exports.delete_refresh_token = async (req, res, next) => {
    const { userId, token } = req.body

    try {
        await RefreshToken.findOneAndUpdate({ userId }, { $pull: { tokens: token } })
        res.sendStatus(204)
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}

exports.forget_password = async (req, res, next) => {
    const { email } = req.body

    try {
        const existingUser = await User.findOne({ email })
        if (!existingUser) {
            return res.status(401).send('Email does not exist')
        }

        const token = jwt.sign({ id: existingUser._id, email: existingUser.email }, process.env.JWT_RESET_SECRET, { expiresIn: '15m' })
        const data = {
            from: 'noreply@gmail.com',
            to: email,
            subject: 'Reset Password',
            text: 'click on the link to reset your password ' + token
        };

        existingUser.updateOne({resetToken : token}, (err) => {
            if (err) {
                return res.status(400).send('password reset error')
            }
            mg.messages().send(data, function (error, body) {
                if (!error) {
                    return res.status(200).json({
                        message: 'Link has been sent to your email'
                    })
                }
            })
        })
        
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}

exports.reset_password = async (req, res, next) => {
    const { resetToken, newPassword } = req.body
    
    try {
        if (!resetToken) {
            return res.status(401).json('Reset token is missing')
        }
        const isValid = jwt.verify(resetToken, process.env.JWT_RESET_SECRET);
        if (!isValid) {
            return res.status(401).send('Incorrect or Expired token')
        }

        const user = await User.findOne({ resetToken })
        if (!user) {
            return res.status(401).send('User with this token does not exist')
        }

        const hashpwd = await bcrypt.hash(newPassword, 10);

        user.updateOne({password: hashpwd, resetToken : ''}, (err) => {
            if (err) {
                return res.status(400).send('Password reset failed')
            }
            else {
                return res.status(200).send('your password have been changed successfully')
            }
        })
    }
    catch (error) {
        return res.status(500).send(error.message)
    }
}