Feature:

Background:
    * url baseUrl
    * def token = karate.get('userToken')
    * header Authorization = 'Bearer ' + token
    * header Content-Type = 'application/json'
    * def deviceId = karate.get('deviceId')
Scenario: Delete a device
    Given path 'device'
    And request { "deviceId": "#(deviceId)" }
    When method delete
    Then status 200
    And match response.message == 'Device deleted successfully'