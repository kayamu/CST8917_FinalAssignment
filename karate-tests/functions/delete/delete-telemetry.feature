Feature:

Background:
    * url baseUrl
    * def userToken = karate.get('userToken')
    * def eventId = karate.get('firstEventId')
    * print 'Event ID:', eventId    
    * header Content-Type = 'application/json'
    * header Authorization = 'Bearer ' + userToken

Scenario: Get telemetry data
    Given path 'telemetry'
    And request { eventId: '#(eventId)' }
    When method delete
    Then status 200

