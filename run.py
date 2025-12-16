import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")

load_dotenv(dotenv_path=ENV_PATH)

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
