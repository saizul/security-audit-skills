import os

DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
API_KEY = os.getenv("API_KEY", "")
SECRET_KEY = "${SECRET_KEY}"
token: str = settings.api_token
password = get_password()
password_field = "password"
REDIS_URL = "redis://localhost:6379/0"
