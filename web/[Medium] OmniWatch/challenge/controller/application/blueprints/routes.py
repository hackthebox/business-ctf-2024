import sys, datetime, os
from flask import Blueprint, current_app, render_template, make_response, request, redirect

from application.util.general import response
from application.util.jwt import create_jwt, verify_jwt
from application.util.database import MysqlInterface

web = Blueprint("web", __name__)

def moderator_middleware(func):
	def check_moderator(*args, **kwargs):
		jwt_cookie = request.cookies.get("jwt")
		if not jwt_cookie:
			return redirect("/controller/login")

		token = verify_jwt(jwt_cookie, current_app.config["JWT_KEY"])
		if not token:
			return redirect("/controller/login")
		
		mysql_interface = MysqlInterface(current_app.config)

		user_id = token.get("user_id")
		account_type = token.get("account_type")
		signature = jwt_cookie.split(".")[-1]
		saved_signature = mysql_interface.fetch_signature(user_id)

		if not user_id or not account_type or not signature or not saved_signature or signature == "":
			return redirect("/controller/login")

		if saved_signature != signature:
			mysql_interface.delete_signature(user_id)
			return redirect("/controller/login")

		if not account_type or account_type not in ["moderator", "administrator"]:
			return redirect("/controller/login")
		
		request.user_data = token
		return func(*args, **kwargs)

	check_moderator.__name__ = func.__name__
	return check_moderator


def administrator_middleware(func):
	def check_moderator(*args, **kwargs):
		jwt_cookie = request.cookies.get("jwt")
		if not jwt_cookie:
			return redirect("/controller/login")

		token = verify_jwt(jwt_cookie, current_app.config["JWT_KEY"])
		if not token:
			return redirect("/controller/login")
		
		mysql_interface = MysqlInterface(current_app.config)

		user_id = token.get("user_id")
		account_type = token.get("account_type")
		signature = jwt_cookie.split(".")[-1]
		saved_signature = mysql_interface.fetch_signature(user_id)

		if not user_id or not account_type or not signature or not saved_signature or signature == "":
			return redirect("/controller/login")

		if saved_signature != signature:
			mysql_interface.delete_signature(user_id)
			return redirect("/controller/login")

		if account_type != "administrator":
			return redirect("/controller/home")
		
		request.user_data = token
		return func(*args, **kwargs)

	check_moderator.__name__ = func.__name__
	return check_moderator


@web.route("/", methods=["GET"])
def index():
	return redirect("/controller/home")


@web.route("/bot_running", methods=["GET"])
def bot_running():
	mysql_interface = MysqlInterface(current_app.config)
	bot_status = mysql_interface.fetch_bot_status()
	return bot_status


@web.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "GET":
		return render_template("login.html", title="OmniWatch - Log-in")

	if request.method == "POST":
		username = request.form.get("username")
		password = request.form.get("password")
		
		if not username or not password:
			return response("Missing parameters"), 400

		mysql_interface = MysqlInterface(current_app.config)
		user_valid = mysql_interface.check_user(username, password)

		if not user_valid:
			return response("Invalid user or password"), 401

		user = mysql_interface.fetch_user_by_username(username)

		jwt_payload = {
			"user_id": user["user_id"],
			"username": username,
			"account_type": user["permissions"]
		}
		
		jwt = create_jwt(jwt_payload, current_app.config["JWT_KEY"])
		mysql_interface.create_or_update_signature(user["user_id"], jwt.split(".")[-1])

		expiration_time = datetime.datetime.now() + datetime.timedelta(minutes=60)
		resp = make_response(redirect("/controller/home"))
		resp.set_cookie("jwt", jwt, expires=expiration_time)
		return resp, 302


@web.route("/logout", methods=["GET"])
@moderator_middleware
def logout():
	mysql_interface = MysqlInterface(current_app.config)
	mysql_interface.delete_signature(request.user_data.get("user_id"))
	resp = make_response(redirect("/controller/login"))
	resp.set_cookie("jwt", "", expires=0)
	return resp, 302


@web.route("/home", methods=["GET"])
@moderator_middleware
def home():
	mysql_interface = MysqlInterface(current_app.config)
	devices = mysql_interface.fetch_all_devices()
	return render_template("home.html", user_data=request.user_data, nav_enabled=True, title="OmniWatch - Home", devices=devices)


@web.route("/device/<id>", methods=["GET"])
@moderator_middleware
def device(id):
	mysql_interface = MysqlInterface(current_app.config)
	device = mysql_interface.fetch_device(id)
	
	if not device:
		return redirect("/controller/home")

	return render_template("device.html", user_data=request.user_data, nav_enabled=True, title=f"OmniWatch - Device {device['device_id']}", device=device)


@web.route("/firmware", methods=["GET", "POST"])
@moderator_middleware
def firmware():
	if request.method == "GET":
		patches_avaliable = ["CyberSpecter_v1.5_config.json", "StealthPatch_v2.0_config.json"]
		return render_template("firmware.html", user_data=request.user_data, nav_enabled=True, title="OmniWatch - Firmware", patches=patches_avaliable)
	
	if request.method == "POST":
		patch = request.form.get("patch")

		if not patch:
			return response("Missing parameters"), 400

		file_data = open(os.path.join(os.getcwd(), "application", "firmware", patch)).read()
		return file_data, 200


@web.route("/admin", methods=["GET"])
@administrator_middleware
def admin():
	flag = os.popen("/readflag").read()
	return render_template("admin.html", user_data=request.user_data, nav_enabled=True, title="OmniWatch - Admin", flag=flag)