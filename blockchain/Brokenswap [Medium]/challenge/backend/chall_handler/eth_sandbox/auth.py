#!/usr/bin/env python
import os

def get_shared_secret():
    return os.getenv("SHARED_SECRET", "e45c7cfb-3fc3-4bef-9574-2ca62b6a556c")