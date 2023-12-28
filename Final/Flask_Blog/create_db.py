"""previous code used to create database; now manually created"""
# Assuming your Flask app is defined in a file named 'your_flask_app.py'
# and your SQLAlchemy database instance is named 'db'

from flasknews import app, db  # Make sure to import 'app' as well

with app.app_context():
    db.create_all()
