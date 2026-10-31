"""Development entrypoint:  python run.py"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(port=5000)  # debug mode comes from FLASK_ENV=development in .env
