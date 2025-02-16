from celery import Celery
from config import Config
from flask import Flask
import logging

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    # ...existing app setup...
    return app

def make_celery(app):
    try:
        celery = Celery(
            app.import_name,
            broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
            backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
        )
        celery.conf.update(app.config)

        class ContextTask(celery.Task):
            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask
        return celery
    except Exception as e:
        logging.error(f"Failed to connect to Celery broker: {e}")
        raise

app = create_app()
celery = make_celery(app)
