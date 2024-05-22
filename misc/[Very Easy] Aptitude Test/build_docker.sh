#!/bin/bash
docker build -t misc_aptitude_test .
docker run  --name=misc_aptitude_test --rm -p1337:1337 -it misc_aptitude_test
