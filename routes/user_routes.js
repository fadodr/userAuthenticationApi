const express = require('express');
const router = express.Router();
const userController = require('../controller/user_controller')

router.post('/login', userController.login_user);
router.post('/signup', userController.signup_user);
router.post('/email-confirmation', userController.activate_user)
router.post('/refresh-token', userController.refresh_token)
router.post('/logout', userController.delete_refresh_token)
router.post('/forgetpassword', userController.forget_password)
router.put('/resetpassword', userController.reset_password)


module.exports = router;