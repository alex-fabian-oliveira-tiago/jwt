/* Imports */
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

/*  Config JSON response */
app.use(express.json())

/*  Import Models */
const User = require('./models/User')

/* Public Routes */
app.get('/', (req, res) => {
    res.status(200)
    res.json({ message: 'Bem vindo a nossa API!' })
})

/* Privates Routes */
app.get('/private/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // Check if User exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ message: 'Usuário não cadastrado!' })
    }

    return res.status(200).json({ user })

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado!' })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch (error) {
        console.log(error)
        return res.status(400).json({ message: 'Token inválido ou expirado! Faça autenticação no sistema novamente...' })
    }
}

/* Register User */
app.post('/usuario/cadastro', async (req, res) => {

    const { name, email, password1, password2 } = req.body

    // Validations
    if (!name || !email || !password1 || !password2) {
        return res.status(422).json({ message: 'Todos os dados devem ser preenchidos!' })
    }

    if (password1 !== password2) {
        return res.status(422).json({ message: 'As senhas devem ser iguais...' })
    }

    // Check if User exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ message: 'Usuário já cadastrado no sistema! Por favor utilize outro e-mail...' })
    }

    // Create a encrypted password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password1, salt)

    // Creating User in Database
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save(user)
        return res.status(201).json({ message: `Usuário cadastrado com sucesso: ${req.body.name}` })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ message: 'Aconteceu um erro no servidor! Tente novamente mais tarde...' })
        // Ou return res.status(500).json({ message: error }) // Não se deve mostrar erros do servidor para o Frontend!!!
    }

    // return res.status(200).json(req.body)
    // return res.status(200).json({ message: 'Dados recebidos: ' + JSON.stringify(req.body) })
    // return res.status(200).json({
    //     message: `Usuário cadastrado com sucesso: ${req.body.name}`
    // })
})

/* Login user */
app.post('/usuario/login', async (req, res) => {
    const { email, password } = req.body

    // Validations
    if (!email || !password) {
        return res.status(422).json({ message: 'O E-mail e a senha devem ser preenchidos!' })
    }

    // Check if User exists
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ message: 'Usuário não cadastrado no sistema! Informe outro e-mail...' })
    }

    // Check if user password match with stored on database
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(401).json({ message: 'A senha digitada não combina com a senha do usuário...' })
    }

    // Formatting a TOKEN to user
    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        }, secret, { expiresIn: 300 }) // O TOKEN expira em 5 minutos...

        return res.status(200).json({ message: 'Autenticação realizada com sucesso!', token })

    } catch (error) {
        //console.log(error)
        return res.status(500).json({ message: 'Aconteceu um erro no servidor! Tente novamente mais tarde...' })
    }

    // return res.status(200).json({ message: 'Validações ok!!!' })

})

/* Credentials */
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

/* Connecting to database and running Server */
mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.k21ep.mongodb.net/jwtdb?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000, () => {
            console.log('Servidor conectado ao MongoDB Atlas e rodando na porta http://127.0.0.1:3000')
        })
    })
    .catch((err) => console.log(err))
