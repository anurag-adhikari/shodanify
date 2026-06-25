"""Entry point. The application lives in the ``shodanify`` package."""
from shodanify import create_app
from shodanify.config import Config

app = create_app()

if __name__ == "__main__":
    app.run(debug=Config.DEBUG, host=Config.HOST, port=Config.PORT)
