Feature: Master Test Runner

Scenario: Run everything in order
  * call read('create-user.feature')
  * call read('user.feature')
  * call read('profile.feature')
