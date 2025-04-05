Feature:

Background:
    * url baseUrl
    * def deviceId = karate.get('deviceId')
    * print 'Device ID:', deviceId
    * header Content-Type = 'multipart/form-data'
    * header Accept = 'application/json'

Scenario: Add telemetry data
  Given path 'telemetry'
  And multipart field deviceId = deviceId
  And multipart field values = '[{ "valueType": "temperature", "value": 25, "longitude": "40.1111", "latitude": "30.1111" }]'
  When method post
  Then status 202
  And match response.message == 'Telemetry data sent to Service Bus Queue successfully'

Scenario: Add telemetry data with normal image
  Given path 'telemetry'
  And multipart field deviceId = deviceId
  And multipart field values = '[{ "valueType": "temperature", "value": 90, "longitude": "41.111", "latitude": "41.511" }]'
  And multipart file image = { read: '../images/nature.jpg', filename: 'nature.jpg', contentType: 'image/jpeg' }
  When method post
  Then status 202
  And match response.message == 'Telemetry data sent to Service Bus Queue successfully'

Scenario: Add telemetry data with fire image
  Given path 'telemetry'
  And multipart field deviceId = deviceId
  And multipart field values = '[{ "valueType": "temperature", "value": "-25", "longitude": "40.5555", "latitude": "45.5555" }]'
  And multipart file image = { read: '../images/fire2.jpg', filename: 'nature.jpg', contentType: 'image/jpeg' }
  When method post
  Then status 202
  And match response.message == 'Telemetry data sent to Service Bus Queue successfully'
