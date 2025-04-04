Feature: Device Management API Tests

Background:
  * url baseUrl
  * def token = karate.get('userToken')
  * header Authorization = 'Bearer ' + token
  * header Content-Type = 'application/json'
  * def deviceId = Math.floor(Math.random() * 10000)
  * karate.set('deviceId', deviceId)

Scenario: Register a new device
  Given path 'device'
  And request {"deviceId":"#(deviceId)","deviceName":"Thermostat","sensorType":"Temperature","location":{"name": "Living Room", "longitude": "40.7128", "latitude": "74.0060"}}
  When method post
  Then status 201
  And match response.message == 'Device registered successfully'