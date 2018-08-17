debug                    = require('debug')('meshblu-authenticator-email-password:device-controller')
_                        = require 'lodash'
validator                = require 'validator'
url                      = require 'url'
Crypto                   = require 'crypto'
stringify                = require 'json-stable-stringify'
Redis                    = require 'redis'
request                  = require 'request'
pepper                   = 'meshblu-test-pepper'
extensionUrl             = 'http://47.98.33.233/meshbluapi/meshblu.php/meshblu/meshbluapi/extensions'
result                   = ''

class DeviceController
  constructor: ({@meshbluHttp, @deviceModel}) ->
    @redisClient = Redis.createClient("6379", "127.0.0.1")

  prepare: (request, response, next) =>
    {email,password,checkCode} = request.body
    return response.status(422).send 'Password required' if _.isEmpty(password)

    query = {}
    email = email.toLowerCase()
    query[@deviceModel.authenticatorUuid + '.id'] = email

    request.email = email
    request.password = password
    request.deviceQuery = query

    keyCode = "#{email}#{checkCode}"
    @redisClient.exists keyCode, (error, result) =>
      if result
        next()
      else
        return response.status(404).send 'checkCode wrong'

  prepareDevices: (request, response, next) =>
    {deviceId,secret} = request.body
    return response.status(422).send 'secret required' if _.isEmpty(secret)
    return response.status(422).send 'deviceId required' if _.isEmpty(deviceId)
  
    deviceId = deviceId.toLowerCase()
    query = 
      deviceId:deviceId
    request.deviceQuery = query

    @meshbluHttp.devices query, (error, devices) =>
      return response.status(500).json error: error.message if error?
      return response.status(423).send 'Mac Address has registered' unless _.isEmpty devices
      next()

  createUser: (request, response) =>
    {deviceQuery, email, password} = request
    debug 'device query', deviceQuery

    @deviceModel.create
      query: deviceQuery
      data:
        type: 'octoblu:user'
      user_id: email
      secret: password
    , @reply(request.body.callbackUrl, email, response)

  createDevices: (request, response) =>
    {deviceQuery} = request
    data = request.body
    console.log "data",data
    debug 'device query', deviceQuery

    @deviceModel.createDevices
      query: deviceQuery
      data: data
    , @replyDevices(response)

  reply: (callbackUrl, email, response) =>
    (error, device) =>
      console.log "callbackUrl",callbackUrl
      if error?
        debug 'got an error', error.message
        if error.message == 'device already exists'
          return response.status(401).json error: "Unable to create user"

        if error.message == @ERROR_DEVICE_NOT_FOUND
          return response.status(401).json error: "Unable to find user"

        return response.status(500).json error: error.message

      @meshbluHttp.generateAndStoreToken device.uuid, (error, device) =>
        console.log '**********', device
        if !callbackUrl
          request.post {url: extensionUrl, form:{'extension':email}}, (err, res, body)=>
            console.log body
            result = JSON.parse body
            if result[0] == 'ERRCODE_1001' || result[0] == 'ERRCODE_1002'
              return response.status(405).send 'generate extension failed'
            else
              return response.status(201).send(device: device)
        else
          uriParams = url.parse callbackUrl, true
          delete uriParams.search
          uriParams.query ?= {}
          uriParams.query.uuid = device.uuid
          uriParams.query.token = device.token
          uri = decodeURIComponent url.format(uriParams)
          response.status(201).location(uri).send(device: device, callbackUrl: uri)

  replyDevices: (response) =>
    (error, device) =>
      if error?
        debug 'got an error', error.message
        if error.message == 'device already exists'
          return response.status(401).json error: "Unable to create user"

        if error.message == @ERROR_DEVICE_NOT_FOUND
          return response.status(401).json error: "Unable to find user"

        return response.status(500).json error: error.message

      @meshbluHttp.generateAndStoreToken device.uuid, (error, device) =>
        return response.status(201).send(device: device) 

  checkOnline:(request, response) =>
      uuid = request.query.uuid
      token = request.query.token
      return response.status(422).send() unless uuid? && token?
      hasher = Crypto.createHash 'sha256'
      hasher.update token
      hasher.update uuid
      hasher.update pepper
      console.log hasher
      hashedToken = hasher.digest 'base64'
      query = {uuid,hashedToken}
      queryStr = stringify(query)
      cacheKey = Crypto.createHash('sha1').update(queryStr).digest('hex')
      key = "datastore:tokens:#{cacheKey}"
      @checkTokenInRedis key, (error, result) =>
        if result
          response.status(200).send status: 'online'
        else
          response.status(503).send status: 'offline'

  checkTokenInRedis: (key, callback) =>
    @redisClient.exists key, callback

  




module.exports = DeviceController
