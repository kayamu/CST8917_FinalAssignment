Feature:

Background:
    * url baseUrl
    * def token = karate.get('userToken')
    * header Authorization = 'Bearer ' + token
    * header Content-Type = 'application/json'
    * def deviceId = karate.get('deviceId')

  Scenario: Update a device
    Given path 'device'
    And request { "deviceId": "#(deviceId)", "update": { "deviceName": "Smart Thermostat" } }
    When method put
    Then status 200
    And match response.message == 'Device updated successfully'    