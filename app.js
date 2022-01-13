/* Imports */
require('dotenv').config()
const exprexx = require('express')
const moogoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const express = require('express')

const app = express()

// Config JSON response
app.use(express.json())

/* Public Routes */
app.get('/', (req, res) => {
    res.status(200)
    res.json({ message: 'Bem vindo a nossa API!' })
})

/* Privates Routes */

/* Register User */
app.post('/auth/register', async(req, res) => {

    const { name, email, password1, password2 } = req.body

    // Validations
    if (!name || !email || !password1 || !password2) {
        return res.status(422).json({ message: "Todos os dados devem ser preenchidos!" })
    }

    return res.status(200).json(req.body)
        // return res.status(200).json({ message: "Dados recebidos: " + JSON.stringify(req.body) })

})

/* Credentials */
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

/* Connecting to database and running Server */
moogoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.k21ep.mongodb.net/jwtdb?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000, () => {
            console.log('Servidor conectado ao MongoDB Atlas e rodando na porta http://127.0.0.1:3000')
        })
    })
    .catch((err) => console.log(err))