Feature: User Operations

Background:
  * url baseUrl
  * header Content-Type = 'application/json'

Scenario: Create a new user
  * call read('../functions/post/create-new-user.feature')
  * call read('../functions/post/login-existing-user.feature')

  * def createDevice = function(i){ karate.call('../functions/post/create-new-device.feature') }
  * karate.repeat(4, createDevice)

#  * call read('../functions/post/create-new-telemetry.feature')

  * call read('../functions/get/get-user.feature')
  * call read('../functions/put/put-user.feature')

  * karate.log('');
  * karate.log('Not ready, waiting...');
  * eval java.lang.Thread.sleep(10000)
  * karate.log('continued');
  
#  * call read('../functions/delete/delete-user.feature')

