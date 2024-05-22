import time, bcrypt, random, uuid, mysql.connector

class MysqlInterface:
	def __init__(self, config):
		self.connection = None
		self.moderator_user = config["MODERATOR_USER"]
		self.moderator_password = config["MODERATOR_PASSWORD"]
		
		while self.connection is None:
			try:
				self.connection = mysql.connector.connect(
					host=config["MYSQL_HOST"],
					database=config["MYSQL_DATABASE"],
					user=config["MYSQL_USER"],
					password=config["MYSQL_PASSWORD"]
				)
			except mysql.connector.Error:
				time.sleep(5)
	

	def __del__(self):
		self.close()


	def close(self):
		if self.connection is not None:
			self.connection.close()


	def query(self, query, args=(), one=False, multi=False):
		cursor = self.connection.cursor()
		results = None

		if not multi:
			cursor.execute(query, args)
			rv = [dict((cursor.description[idx][0], value)
				for idx, value in enumerate(row)) for row in cursor.fetchall()]
			results = (rv[0] if rv else None) if one else rv
		else:
			results = []
			queries = query.split(";")
			for statement in queries:
				cursor.execute(statement, args)
				rv = [dict((cursor.description[idx][0], value)
					for idx, value in enumerate(row)) for row in cursor.fetchall()]
				results.append((rv[0] if rv else None) if one else rv)
				self.connection.commit()
	
		return results


	def generate_random_device_name(self):
		adjectives = ["Sleek", "Smart", "Quantum", "Advanced", "Nano", "Futuristic", "Intelligent", "Innovative"]
		nouns = ["Tracker", "Device", "Gadget", "Sensor", "Locator", "Beacon", "Module", "Widget"]

		device_name = f"{random.choice(adjectives)}_{random.choice(nouns)}"
		device_name += f"_{str(uuid.uuid4())[:8]}"

		return device_name


	def generate_random_manufacturer(self):
		manufacturers = ["TechCorp", "InnoTech", "FutureTech", "QuantumTech", "NexGen", "EvoInnovations", "SmartSolutions", "CyberDyne"]
		manufacturer = random.choice(manufacturers)

		return manufacturer


	def generate_random_communication_protocol(self):
		protocols = ["HTTP", "MQTT", "CoAP", "WebSocket", "Bluetooth", "LoRa", "5G", "QuantumSecure"]
		protocol = random.choice(protocols)

		return protocol


	def migrate(self):
		create_users_query = """CREATE TABLE IF NOT EXISTS users (
			user_id INT AUTO_INCREMENT PRIMARY KEY,
			permissions VARCHAR(255) NOT NULL,
			username VARCHAR(255) NOT NULL,
			password VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		"""

		create_devices_table = """CREATE TABLE IF NOT EXISTS devices (
			device_id INT AUTO_INCREMENT PRIMARY KEY,
			device_name VARCHAR(255) NOT NULL,
			manufacturer VARCHAR(50),
			tracking_type VARCHAR(255) NOT NULL,
			battery_level INT,
			encryption_level VARCHAR(255) NOT NULL,
			communication_protocol VARCHAR(20) NOT NULL,
			firmware_version VARCHAR(10),
			activation_status VARCHAR(20),
			last_update_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		"""

		create_signatures_table = """CREATE TABLE IF NOT EXISTS signatures (
			user_id INT PRIMARY KEY,
			signature VARCHAR(255) NOT NULL
		);
		"""

		create_bot_status_table = """CREATE TABLE IF NOT EXISTS bot_status (
			bot_id INT AUTO_INCREMENT PRIMARY KEY,
			status VARCHAR(20) NOT NULL,
			last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);"""

		self.query(create_users_query)
		self.query(create_devices_table)
		self.query(create_signatures_table)
		self.query(create_bot_status_table)

		self.register_user("moderator", self.moderator_user, self.moderator_password)
		self.initialize_bot_status()

		for _ in range(15):
			random_device_name = self.generate_random_device_name()
			random_manufacturer = self.generate_random_manufacturer()
			random_tracking_type = random.choice(["GPS", "Biometric", "Nano", "Quantum"])
			random_battery_level = random.randint(0, 100)
			random_encryption_level = random.choice(["Basic", "Advanced", "Quantum-Proof"])
			random_communication_protocol = self.generate_random_communication_protocol()
			random_firmware_version = f"v{random.randint(1, 9)}.{random.randint(0, 9)}"
			random_activation_status = random.choice(["Active", "Inactive"])

			self.add_device(
				random_device_name,
				random_manufacturer,
				random_tracking_type,
				random_battery_level,
				random_encryption_level,
				random_communication_protocol,
				random_firmware_version,
				random_activation_status
			)

	
	def register_user(self, permissions, username, password):
		password_bytes = password.encode("utf-8")
		salt = bcrypt.gensalt()
		password_hash = bcrypt.hashpw(password_bytes, salt).decode()
		self.query("INSERT INTO users(permissions, username, password) VALUES(%s, %s, %s)", (permissions, username, password_hash,))
		self.connection.commit()
		return True


	def check_user(self, username, password):
		user = self.query("SELECT password FROM users WHERE username = %s", (username,), one=True)

		if not user:
			return False
		
		password_bytes = password.encode("utf-8")
		password_encoded = user["password"].encode("utf-8")
		matched = bcrypt.checkpw(password_bytes, password_encoded)
		
		if matched:
			return True
		
		return False

	
	def fetch_user_by_username(self, username):
		user = self.query("SELECT * FROM users WHERE username = %s", (username,), one=True)

		if not user:
			return False
		
		return user


	def add_device(
		self,
		device_name,
		manufacturer,
		tracking_type,
		battery_level,
		encryption_level,
		communication_protocol,
		firmware_version,
		activation_status
	):
		query = """
			INSERT INTO devices(
				device_name,
				manufacturer,
				tracking_type,
				battery_level,
				encryption_level,
				communication_protocol,
				firmware_version,
				activation_status
			) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)
		"""
		self.query(
			query,
			(
				device_name,
				manufacturer,
				tracking_type,
				battery_level,
				encryption_level,
				communication_protocol,
				firmware_version,
				activation_status
			)
		)
		self.connection.commit()


	def fetch_all_devices(self):
		query = "SELECT * FROM devices"
		devices = self.query(query)
		return devices


	def fetch_device(self, device_id):
		query = f"SELECT * FROM devices WHERE device_id = '{device_id}'"
		device = self.query(query, multi=True)[0][0]
		return device


	def create_signature(self, user_id, signature):
		self.query("INSERT INTO signatures(user_id, signature) VALUES(%s, %s)", (user_id, signature,))
		self.connection.commit()
		return True


	def update_signature(self, user_id, new_signature):
		self.query("UPDATE signatures SET signature = %s WHERE user_id = %s", (new_signature, user_id,))
		self.connection.commit()
		return True

		
	def create_or_update_signature(self, user_id, signature):
		existing_signature = self.fetch_signature(user_id)

		if existing_signature:
			self.update_signature(user_id, signature)
		else:
			self.create_signature(user_id, signature)

		return True


	def fetch_signature(self, user_id):
		signature = self.query("SELECT signature FROM signatures WHERE user_id = %s", (user_id,), one=True)
		return signature["signature"] if signature else False


	def delete_signature(self, user_id):
		self.query("DELETE FROM signatures WHERE user_id = %s", (user_id,))
		self.connection.commit()
		return True

	
	def initialize_bot_status(self):
		initial_bot_status_query = "INSERT INTO bot_status (bot_id, status) VALUES (1, 'not_running') ON DUPLICATE KEY UPDATE last_updated = CURRENT_TIMESTAMP;"
		self.query(initial_bot_status_query)
		self.connection.commit()


	def update_bot_status(self, status):
		query = "UPDATE bot_status SET status = %s, last_updated = CURRENT_TIMESTAMP WHERE bot_id = 1;"
		self.query(query, (status,))
		self.connection.commit()


	def fetch_bot_status(self):
		query = "SELECT status FROM bot_status WHERE bot_id = 1;"
		result = self.query(query, one=True)
		return result["status"] if result else None