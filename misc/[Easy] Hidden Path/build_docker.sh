#!/bin/bash
docker build -t misc_hidden_path .
docker run --name=misc_hidden_path --rm -p1337:1337 -it misc_hidden_path
