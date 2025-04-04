Feature: Add a device to an existing user

Background:
  * url baseUrl

Scenario: Login, create a new device, and add telemetry data
  # Login existing user
  * callonce read('../functions/post/login-existing-user.feature')

  # Create a new device
  * call read('../functions/post/create-new-device.feature')

  # Add telemetry data
  * call read('../functions/post/create-new-telemetry.feature')
