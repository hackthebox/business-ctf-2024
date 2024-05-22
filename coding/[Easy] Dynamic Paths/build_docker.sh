#!/bin/bash
docker build --tag=dynamic-paths .
docker run -p 1337:1337 --rm --name=dynamic-paths -it dynamic-paths