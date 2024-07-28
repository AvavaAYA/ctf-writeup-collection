#!/bin/bash
docker build -t user_managment .
docker run -p 1337:1337 user_managment