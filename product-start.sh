#!/bin/bash


# For development usage only

env \
  forever start -l /data/meshblu-authenticator-email-password-2.0.13/forever.log -a server.js
