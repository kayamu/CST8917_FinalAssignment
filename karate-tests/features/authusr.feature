Feature: Authenticated User Login Test

Background:
  * url baseUrl
  * def loginBody = { email: email, password: password }

Scenario: Login and Get Token
  Given path '/user/login'
  And request loginBody
  When method post
  Then status 200
  * def token = response.token
  * print 'JWT Token:', token

Scenario: Get Authenticated User Info
  Given path '/user'
  And header Authorization = 'Bearer ' + token
  When method get
  Then status 200
  And match response.email == email

Scenario: Update User Info
  Given path '/user'
  And header Authorization = 'Bearer ' + token
  And request { firstName: 'Updated', lastName: 'User', phone: '1234567890' }
  When method put
  Then status 200