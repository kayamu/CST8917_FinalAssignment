Feature: Telemetry API Tests

  Background:
    * url baseUrl
    * header Authorization = 'Bearer ' + token

  Scenario: Add telemetry data
    Given path 'telemetry'
    And multipart field deviceId = '12345'
    And multipart field values = [{ "valueType": "Temperature", "value": 25 }]
    When method post
    Then status 201
    And match response.message == 'Telemetry data added successfully'

  Scenario: Get telemetry data
    Given path 'telemetry'
    And param deviceId = '12345'
    When method get
    Then status 200
    And match response[0].deviceId == '12345'

  Scenario: Delete telemetry data
    Given path 'telemetry'
    And request { "eventId": "67890" }
    And header Content-Type = 'application/json'
    When method delete
    Then status 200
    And match response.message == 'Telemetry data deleted successfully'