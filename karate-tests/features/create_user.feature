Feature: Create User and Capture Token

Scenario: Create a new user
  Given path 'user'
  And request { "firstName": "John", "lastName": "Doe", "email": "john.doe@example.com", "password": "password123", "phone": "1234567890" }
  And header Content-Type = 'application/json'
  When method post
  Then status 201
  * def token = response.token
  * karate.set('userToken', token)
