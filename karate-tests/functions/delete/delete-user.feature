Feature: User Operations

Background:
  * url baseUrl
  * def userToken = karate.get('userToken')
  * header Content-Type = 'application/json'
  * header Authorization = 'Bearer ' + userToken

Scenario: Delete a user
    Given path 'user'
    When method delete
    Then status 200
    And match response.message == 'User deleted successfully'  