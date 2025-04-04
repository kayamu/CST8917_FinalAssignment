Feature:

Background:
    * url baseUrl
    * def token = karate.get('userToken')
    * match token != null
    * header Authorization = 'Bearer ' + token
    * header Content-Type = 'application/json'

Scenario: Register a new device
    Given path 'devices'
    When method get
    Then status 200
    * def deviceId = response[0].deviceId
    * karate.set('deviceId', deviceId)
    * print 'First Device ID:', deviceId
