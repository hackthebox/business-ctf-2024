import time, random

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

from application.util.database import MysqlInterface

def run_scheduled_bot(config):
	try:
		bot_runner(config)
	except Exception:
		mysql_interface = MysqlInterface(config)
		mysql_interface.update_bot_status("not_running")


def bot_runner(config):
	mysql_interface = MysqlInterface(config)
	mysql_interface.update_bot_status("running")

	chrome_options = Options()

	chrome_options.add_argument("headless")
	chrome_options.add_argument("no-sandbox")
	chrome_options.add_argument("ignore-certificate-errors")
	chrome_options.add_argument("disable-dev-shm-usage")
	chrome_options.add_argument("disable-infobars")
	chrome_options.add_argument("disable-background-networking")
	chrome_options.add_argument("disable-default-apps")
	chrome_options.add_argument("disable-extensions")
	chrome_options.add_argument("disable-gpu")
	chrome_options.add_argument("disable-sync")
	chrome_options.add_argument("disable-translate")
	chrome_options.add_argument("hide-scrollbars")
	chrome_options.add_argument("metrics-recording-only")
	chrome_options.add_argument("no-first-run")
	chrome_options.add_argument("safebrowsing-disable-auto-update")
	chrome_options.add_argument("media-cache-size=1")
	chrome_options.add_argument("disk-cache-size=1")

	client = webdriver.Chrome(options=chrome_options)

	client.get("http://127.0.0.1:1337/controller/login")

	time.sleep(3)
	client.find_element(By.ID, "username").send_keys(config["MODERATOR_USER"])
	client.find_element(By.ID, "password").send_keys(config["MODERATOR_PASSWORD"])
	client.execute_script("document.getElementById('login-btn').click()")
	time.sleep(3)

	client.get(f"http://127.0.0.1:1337/oracle/json/{str(random.randint(1, 15))}")

	time.sleep(10)

	mysql_interface.update_bot_status("not_running")
	client.quit()