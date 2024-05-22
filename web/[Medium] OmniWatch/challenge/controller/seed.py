from application.app import app
from application.util.database import MysqlInterface

if __name__ == "__main__":
    mysql_interface = MysqlInterface(app.config)
    mysql_interface.migrate()