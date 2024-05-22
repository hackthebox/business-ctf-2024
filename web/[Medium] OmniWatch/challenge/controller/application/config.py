import os
from dotenv import load_dotenv

load_dotenv()

class Config(object):
	JWT_KEY = open("/app/jwt_secret.txt", "r").read()
	MYSQL_HOST = os.getenv("MYSQL_HOST")
	MYSQL_DATABASE = os.getenv("MYSQL_DATABASE")
	MYSQL_USER = os.getenv("MYSQL_USER")
	MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
	MODERATOR_USER = os.getenv("MODERATOR_USER")
	MODERATOR_PASSWORD = os.getenv("MODERATOR_PASSWORD")


class ProductionConfig(Config):
	pass


class DevelopmentConfig(Config):
	DEBUG = False


class TestingConfig(Config):
	TESTING = False