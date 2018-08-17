debug = require('debug')('meshblu-authenticator-email-password:forgot-controller')
Redis = require 'redis'
_ = require 'lodash'
url = require 'url'
querystring = require 'querystring'

class ForgotPasswordController
  constructor: ({@deviceModel, @forgotPasswordModel}) ->
    @redisClient = Redis.createClient("6379", "127.0.0.1")

  infoCheck: (request, response, next) =>
    email = request.body.email
    checkCode = request.body.checkCode
    keyCode = "#{email}#{checkCode}"
    @redisClient.exists keyCode, (error, result) =>
      if result
        next()
      else
        return response.status(402).send "forgot checkCode error"
  
  forgot: (request, response) =>
    @forgotPasswordModel.forgot request.body.email, request.body.checkCode, (error, data) =>
      if error
        return response.status(404).send(error.message) if error.message == 'Device not found for email address'
        return response.status(401).send('Cannot write to this device') if error.message == 'unauthorized'
        return response.status(500).send(error.message)

      decode = url.parse data.request.body
      deviceUuidToken = querystring.parse decode.href
      return response.status(201).send deviceUuidToken

  reset: (request, response) =>
    {device,token,password} = request.body
    console.log device, token, password
    return response.status(422).send() unless device? && token? && password?
    @forgotPasswordModel.reset device, token, password, (error) =>
      return response.status(500).send(error.message) if error
      response.send(201)


  checkOldPassword: (request, response, next) =>
    tel = request.body.tel
    uuid = request.body.device
    oldPassword = request.body.oldPassword
    query = {}
    query[@deviceModel.authenticatorUuid + '.id'] = tel
    @deviceModel.findVerifiedSecret query: query, password: oldPassword, (error, data) =>
      if data
        next()
      else
        return response.status(402).send "oldPassword error"

module.exports = ForgotPasswordController
