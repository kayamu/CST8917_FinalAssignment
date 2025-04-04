Feature: User Operations

Background:
  * url baseUrl
  * def userToken = karate.get('userToken')
  * def email = karate.get('email') 
  * header Content-Type = 'application/json'
  * header Authorization = 'Bearer ' + userToken

Scenario: Get user details
    Given path 'user'
    When method get
    Then status 200
    And match response.email == '#(email)'
    * def devices = response.Devices
    * def firstDeviceId = devices[0].deviceId
    * karate.set('deviceId', firstDeviceId)
    * print 'First Device ID:', firstDeviceId
  