Feature: Creating new user and get token

    Background:
    * url baseUrl
    * header Content-Type = 'application/json'
    * def randomString = function(length){ return java.util.UUID.randomUUID().toString().replaceAll('-', '').substring(0, length) }
    * def userName = randomString(8)
    * karate.set('userName', userName)
    * def lastName = randomString(10)
    * karate.set('lastName', lastName)
    * def email = userName + '@example.com'
    * karate.set('email', email)
    * def password = randomString(12)
    * karate.set('password', password)
    * def phone = '123' + randomString(7)
    * karate.set('phone', phone)    

    Scenario: Create a new user and capture token
        Given path 'user'
        And request {"firstName": "#(userName)","lastName": "#(lastName)","email": "#(email)", "password": "#(password)", "phone": "#(phone)"} 
        When method post
        Then status 201
        And match response.message == 'User created successfully'
        * def token = response.token
        * karate.set('userToken', token)
