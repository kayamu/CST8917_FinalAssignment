#!/bin/bash
java -jar karate.jar features/
python3 -m http.server --directory  /workspaces/CST8917_FinalAssignment/karate-tests/target/ 8080
