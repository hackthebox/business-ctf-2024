#!/bin/bash
sudo docker build --tag=computational-recruitment .
sudo docker run -p 1337:1337 --rm --name=computational-recruitment -it computational-recruitment