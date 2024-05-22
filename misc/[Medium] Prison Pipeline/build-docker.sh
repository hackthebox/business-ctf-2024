#!/bin/bash
docker rm -f misc_prison_pipeline
docker build -t misc_prison_pipeline .
docker run --name=misc_prison_pipeline --rm -p1337:1337 -it misc_prison_pipeline
