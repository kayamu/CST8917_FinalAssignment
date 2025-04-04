Feature:

Background:
    * url baseUrl
    * header Content-Type = 'application/json'
  
Scenario:
    * callonce read('../functions/post/login-existing-user.feature')
    * call read('../functions/post/create-new-device.feature')
    * call read('../functions/get/get-device.feature')
    * call read('../functions/put/put-device.feature')
    * call read('../functions/delete/delete-device.feature')




    


