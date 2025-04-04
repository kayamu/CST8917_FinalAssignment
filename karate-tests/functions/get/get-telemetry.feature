Feature:

Background:
    * url baseUrl
    * def userToken = karate.get('userToken')
    * def deviceId = karate.get('firstDeviceId')
    * print 'Device ID:', deviceId    
    * header Content-Type = 'application/json'
    * header Authorization = 'Bearer ' + userToken


Scenario: Get telemetry data
    Given path 'telemetry'
    And param deviceId = deviceId
    When method get
    Then status 200
    * def firstEventId = response[0].eventId
    * karate.set('firstEventId', firstEventId)
    * print 'First Event ID:', firstEventId    



