import os
from flask import jsonify

generate = lambda x: os.urandom(x).hex()

def response(message):
    return jsonify({"message": message})