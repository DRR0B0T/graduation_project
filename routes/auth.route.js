const {Router} = require('express')
const router = Router()
const User = require('../models/User')
//require 2 functions from express validator
const {check, validationResult} = require('express-validator')
//require шифрование пароля
const bcrypt = require('bcryptjs')
//web token require
const jwt = require('jsonwebtoken')


//В req лежит ответ от клиента, в res лежит ответ
router.post('/registration',
  [
    check('email', 'Некорректный email').isEmail(),
    check('password', 'Некорректный пароль, введите не менее 6 символов').isLength({ min: 6 })
  ],
  async (req,res) => {
  try {
    //валидация ошибок
    const errors = validationResult(req)
    //если ошибка есть, то возвращаем ответ со статусом 400
    if(!errors.isEmpty()) {
      return res.status(400).json({
        //возвращаем объект с полем errors, выводим массив с ошибками
        errors: errors.array(),
        message: 'Некорректные данные при регистрации'
      })
    }

    const { email, password } = req.body

    const isUsed = await User.findOne({ email })
    //redirect 300 status
    if (isUsed) {
     return  res.status(300).json({message: 'Данный Email уже занят, попробуйте другой.'})
    }
    //хэширование пароля
    const hashedPassword = await bcrypt.hash(password, 12)

    //create new User
    const user = new User ({
      email, password: hashedPassword
    })
    //save to DB
    await user.save()
    //when we create user
    res.status(201).json({message: 'Пользователь создан'})
  } catch (e) {
    console.error(e)
  }
})

router.post('/login',
  [
    check('email', 'Некорректный email').isEmail(),
    check('password', 'Некорректный пароль').exists()//проверка что пароль есть
  ],
  async (req,res) => {
    try {
      //валидация ошибок
      const errors = validationResult(req)
      //если ошибка есть, то возвращаем ответ со статусом 400
      if(!errors.isEmpty()) {
        return res.status(400).json({
          //возвращаем объект с полем errors, выводим массив с ошибками
          errors: errors.array(),
          message: 'Некорректные данные при регистрации'
        })
      }

      const { email, password } = req.body
      //ищем пользователя
      const user = await User.findOne({email})

      //если его нет то
      if(!user) {
        return res.status(400).json({message: 'Такого пользователя нет в базе!'})
      }

      //если же он есть расшифровываем пароль и сверяем с текущим
      const isMatched = bcrypt.compare(password, user.password)


      if(!isMatched){
        return res.status(400).json({message: 'Пароли не совпадают!'})
      }

      const jwtSecret = 'sjfdsd556dsdfaevfopw'

      const token = jwt.sign(
        {userId: user.id},
        jwtSecret,
        {expiresIn: '1h'}
      )

      res.json({token, userId: user.id})

    } catch (e) {
      console.error(e)
    }
  })

module.exports = router;