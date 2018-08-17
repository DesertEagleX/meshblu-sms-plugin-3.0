debug = require('debug')('meshblu-authenticator-email-password:sessions-controller')
url = require 'url'
Crypto                   = require 'crypto'
pepper                   = 'meshblu-test-pepper'
stringify                = require 'json-stable-stringify'
Redis                    = require 'redis'

class SessionController
  constructor: ({@meshbluHttp, @deviceModel}) ->
    @redisClient = Redis.createClient("6379", "127.0.0.1")

  create: (request, response) =>
    {email,password,callbackUrl} = request.body
    query = {}
    email = email.toLowerCase()
    query[@deviceModel.authenticatorUuid + '.id'] = email
    console.log query

    deviceFindCallback = (error, foundDevice) =>
      debug 'device find error', error if error?
      debug 'device find', foundDevice

      return response.status(401).send error?.message unless foundDevice

      debug 'about to generateAndStoreToken', foundDevice.uuid
      @meshbluHttp.generateAndStoreToken foundDevice.uuid, (error, device) =>
        return response.status(201).send(device:device) unless callbackUrl?

        uriParams = url.parse callbackUrl, true
        delete uriParams.search
        uriParams.query ?= {}
        uriParams.query.uuid = device.uuid
        uriParams.query.token = device.token
        uri = decodeURIComponent url.format(uriParams)

        response.status(201).location(uri).send(device: device, callbackUrl: uri)
    @deviceModel.findVerified query: query, password: password, deviceFindCallback

  devicesLogin:(request, response) =>
    {deviceId,password} = request.body
    deviceId = deviceId.toLowerCase()
    query = {
      deviceId: deviceId
      }     
    console.log query

    deviceFindCallback = (error, foundDevice) =>
      debug 'device find error', error if error?
      debug 'device find', foundDevice
      return response.status(401).send error?.message unless foundDevice

      debug 'about to generateAndStoreToken', foundDevice.uuid
      @meshbluHttp.generateAndStoreToken foundDevice.uuid, (error, device) =>
        return response.status(201).send(device:device)

    @deviceModel.findVerifiedSecret query: query, password: password, deviceFindCallback

  logout: (request, response) => 
    uuid = request.body.uuid
    token = request.body.token
    hasher = Crypto.createHash 'sha256'
    hasher.update token
    hasher.update uuid
    hasher.update pepper
    hashedToken = hasher.digest 'base64'
    console.log hashedToken,'**********************************hashedToken****************'
    query = {uuid,hashedToken}
    queryStr = stringify(query)
    cacheKey = Crypto.createHash('sha1').update(queryStr).digest('hex')
    key = "datastore:tokens:#{cacheKey}"
    @deleteTokenInRedis key, (error, result) =>
      if result
        response.status(200).send status: 'succeed'
      else
        response.status(503).send status: 'failure'   

  deleteTokenInRedis: (key, callback) =>
    console.log @redisClient.del
    console.log key,'***************'
    @redisClient.del key, callback

module.exports = SessionController
