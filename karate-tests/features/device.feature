Feature: Device Management API Tests

  Background:
    * url baseUrl
    * def token = karate.get('userToken')
    * header Authorization = 'Bearer ' + token
    * header Content-Type = 'application/json'

  Scenario: Register a new device
    Given path 'device'
    And request { "deviceId": "12345", "deviceName": "Thermostat", "sensorType": "Temperature", "location": { "name": "Living Room", "longitude": "40.7128", "latitude": "74.0060" } }
    When method post
    Then status 201
    And match response.message == 'Device registered successfully'

  Scenario: Update a device
    Given path 'device'
    And request { "deviceId": "12345", "update": { "deviceName": "Smart Thermostat" } }
    When method put
    Then status 200
    And match response.message == 'Device updated successfully'

  Scenario: Delete a device
    Given path 'device'
    And request { "deviceId": "12345" }
    When method delete
    Then status 200
    And match response.message == 'Device deleted successfully'