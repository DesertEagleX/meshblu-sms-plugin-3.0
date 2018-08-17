cors      = require 'cors'
{DeviceAuthenticator}    = require 'meshblu-authenticator-core'
DeviceController         = require './controllers/device-controller'
ForgotPasswordController = require './controllers/forgot-password-controller'
ForgotPasswordModel      = require './models/forgot-password-model'
SessionController        = require './controllers/session-controller'

class Routes
  constructor: ({@app, deviceModel, meshbluHttp}) ->
    @deviceController         = new DeviceController {meshbluHttp, deviceModel}
    @forgotPasswordModel      = new ForgotPasswordModel
      uuid: deviceModel.authenticatorUuid
      mailgunKey: process.env.MAILGUN_API_KEY
      mailgunDomain: process.env.MAILGUN_DOMAIN || 'octoblu.com'
      passwordResetUrl: process.env.PASSWORD_RESET_URL
      meshbluHttp: meshbluHttp

    @forgotPasswordController = new ForgotPasswordController {deviceModel, @forgotPasswordModel}
    @sessionController        = new SessionController {meshbluHttp, deviceModel}

  register: =>
    @app.options '*', cors()
    @app.get  '/',@deviceController.checkOnline
    @app.post '/users', @deviceController.prepare, @deviceController.createUser
    @app.post '/devices', @deviceController.prepareDevices, @deviceController.createDevices
    @app.post '/sessions', @sessionController.create
    @app.post '/devicesSessions', @sessionController.devicesLogin
    @app.delete '/logout',@sessionController.logout
    #@app.put '/devices', @deviceController.prepare, @deviceController.update   
    #@app.post '/forgot', @forgotPasswordController.infoCheck, @forgotPasswordController.forgot
    #@app.post '/reset', @forgotPasswordController.reset 
    #@app.get '/auth', 
    #@app.get '/forcode',        
    #@app.post '/modify', 
    #@app.get '/check', 
    #@app.get '/findDevices',
  
module.exports = Routes
