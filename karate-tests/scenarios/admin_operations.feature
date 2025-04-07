Feature: User Operations

Background:
  * url baseUrl
  * header Content-Type = 'application/json'

Scenario: Create a new user
  * call read('../functions/post/login-existing-user.feature')

  * def createDevice = function(i){ karate.call('../functions/post/create-new-device.feature') }
  * karate.repeat(5, createDevice)

#  * call read('../functions/post/create-new-telemetry.feature')

  * call read('../functions/get/get-user.feature')

  * karate.log('');
  * karate.log('Not ready, waiting...');
  * eval java.lang.Thread.sleep(5000)
  * karate.log('continued');
  

