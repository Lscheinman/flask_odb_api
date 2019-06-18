from flask import Flask
from apiserver.blueprints.home import home
from apiserver.blueprints.users import users
from apiserver.blueprints.chatbot import chatbot

def create_app():

    app = Flask(__name__)
    app.register_blueprint(home)
    app.register_blueprint(users)
    app.register_blueprint(chatbot)

    return app


