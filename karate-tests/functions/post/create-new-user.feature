Feature: Creating new user and get token

    Background:
    * url baseUrl
    * header Content-Type = 'application/json'
    * def randomString = function(length){ return java.util.UUID.randomUUID().toString().replaceAll('-', '').substring(0, length) }
    * def username = randomString(8)
    * karate.set('username', username)
    * def name = randomString(8)
    * def surname = randomString(10)
    * def address = randomString(20)
    * def phone = '123' + randomString(7)
    * def email = userName + '@example.com'
    * karate.set('email', email)
    * def password = randomString(12)
    * karate.set('password', password)
    * def emergency_contact = randomString(8)

    Scenario: Create a new user and capture token
        Given path 'user'
        And request {
            "username": "#(username)",            
            "name": "#(name)",
            "surname": "#(surname)",
            "email": "#(email)",
            "password": "#(password)",
            "phone": "#(phone)",
            "address": "#(address)",
            "emergencyContact": "#(emergency_contact)"
        }
        When method post
        Then status 201
        And match response.message == 'User created successfully'
        * def token = response.token
        * karate.set('userToken', token)
