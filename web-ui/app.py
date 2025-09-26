from flask import Flask
import os
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except Exception:
    pass

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-env')

from modules.db import init_db
from modules.user import user_bp
from modules.admin import admin_bp

app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8001, debug=True)

 
