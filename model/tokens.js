const mongoose = require('mongoose')
const { schema } = require('./user')

const refreshTokenSchema = new mongoose.Schema({
    userId: {
        type : String
    },
    tokens : [String]
})

module.exports = mongoose.model('RefreshToken', refreshTokenSchema)