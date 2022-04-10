const express = require('express');
const mongoose = require('mongoose')
const app = express();
require('dotenv').config();
const port = process.env.PORT || 3000;

const userRoutes = require('./routes/user_routes');
app.use(express.json());

app.use('/api/user', userRoutes);


app.use((req, res, next) => {
    const error = new Error('Page not found')
    error.statusCode = 404
    next(error)
})

app.use((error, req, res, next) => {
    res.status(error.statusCode).send(error.message)
})

mongoose.connect('mongodb://localhost:27017').then((_) => {
    console.log('database connected')
}).catch((error) => {
    console.log(error.message)
})

app.listen(port, () => {
    console.log('listening on port ' + port);
});