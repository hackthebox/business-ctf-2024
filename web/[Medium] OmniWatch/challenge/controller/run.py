import time, schedule, threading

from application.app import app
from application.util.bot import run_scheduled_bot

def run_flask_app():
    app.run(host="0.0.0.0", port=3000, threaded=True, debug=False)


if __name__ == "__main__":
    schedule.every(0.5).minutes.do(run_scheduled_bot, app.config)

    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.start()

    while True:
        schedule.run_pending()
        time.sleep(1)