Feature: Conditions API Tests

  Background:
    * url baseUrl
    * header Authorization = 'Bearer ' + token

  Scenario: Create a condition
    Given path 'conditions'
    And request { "deviceId": "12345", "valueType": "Temperature", "minValue": 10, "maxValue": 30, "unit": "Celsius" }
    And header Content-Type = 'application/json'
    When method post
    Then status 201
    And match response.created_conditions[0].valueType == 'Temperature'

  Scenario: Get conditions
    Given path 'conditions'
    And param deviceId = '12345'
    When method get
    Then status 200
    And match response[0].deviceId == '12345'

  Scenario: Update a condition
    Given path 'conditions'
    And request { "conditionId": "abcdef123456", "minValue": 15, "maxValue": 25 }
    And header Content-Type = 'application/json'
    When method put
    Then status 200
    And match response.message == 'Condition updated successfully'

  Scenario: Delete a condition
    Given path 'conditions'
    And request { "conditionId": "abcdef123456" }
    And header Content-Type = 'application/json'
    When method delete
    Then status 200
    And match response.message == 'Condition deleted successfully'