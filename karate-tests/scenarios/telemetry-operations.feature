Feature:

Background:
    * url baseUrl
    * header Content-Type = 'application/json'
  
Scenario:
    * callonce read('../functions/post/login-existing-user.feature')
    * call read('../functions/get/get-user.feature')
    * call read('../functions/post/create-new-telemetry.feature')
    * call read('../functions/get/get-telemetry.feature')
    * call read('../functions/delete/delete-telemetry.feature')




    

