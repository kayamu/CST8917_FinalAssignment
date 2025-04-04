Feature: User authentication

Background:
  * url baseUrl
  * header Content-Type = 'application/json'
  * def email = karate.get('email') ? karate.get('email') : karate.config.email
  * def password = karate.get('password') ? karate.get('password') : karate.config.password

@login
Scenario: Get JWT token
  Given path 'user', 'login'
  And request { email: '#(email)', password: '#(password)' }
  When method post
  Then status 200
  * match response.token != null
  * def token = response.token
  * karate.set('userToken', token)