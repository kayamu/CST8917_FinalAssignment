Feature: User Operations

Background:
  * url baseUrl
  * def userToken = karate.get('userToken')
  * header Content-Type = 'application/json'
  * header Authorization = 'Bearer ' + userToken
  * def randomString = function(length){ return java.util.UUID.randomUUID().toString().replaceAll('-', '').substring(0, length) }
  * def userName = randomString(8)
  * def lastName = randomString(10)

Scenario: Update user information
    Given path 'user'
    And request { "firstName": "#(userName)", "lastName": "#(lastName)" }
    When method put
    Then status 200
    And match response.message == 'User updated successfully'