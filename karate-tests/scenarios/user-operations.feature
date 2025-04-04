Feature: User Operations

Background:
  * url baseUrl
  * header Content-Type = 'application/json'

Scenario: Create a new user
  * call read('../functions/post/create-new-user.feature')
  * call read('../functions/post/login-existing-user.feature')
  * call read('../functions/post/create-new-device.feature')
  * call read('../functions/post/create-new-telemetry.feature')

  * call read('../functions/get/get-user.feature')
  * call read('../functions/put/put-user.feature')
  * call read('../functions/delete/delete-user.feature')

