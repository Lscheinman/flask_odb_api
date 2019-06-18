from flask import Blueprint, jsonify, request
from apiserver.utils import get_datetime, randomString
from apiserver.blueprints.users.views import odbserver # For authorizing users
from apiserver.blueprints.chatbot.models import ChatServer

chatbot = Blueprint('chatbot', __name__)
# Set up the Chatserver basing the DB storage on the User ODB
CB = ChatServer()
odbserver.create_user({
    'userName': CB.uuid,
    'email': 'Chatbot@email.com',
    'passWord': randomString(36)})


@chatbot.route('/chatbot/send_message', methods=['POST'])
def send_message():

    auth = odbserver.auth_user(request.headers['Authorization'])
    if auth:
        return jsonify(auth)
    form = request.form.to_dict(flat=True)
    response = CB.send_message(message=form['message'], conversation_id=form['conversationId'])

    odbserver.send_message({
        "text": response['message'],
        "title": response['skill'],
        "sender": form['userName'],
        "receiver": CB.uuid,
        "sessionId": request.headers['SESSIONID']
    })
    odbserver.send_message({
        "text": response['response'],
        "title": response['skill'],
        "sender": CB.uuid,
        "receiver": form['userName'],
        "sessionId": request.headers['SESSIONID']
    })

    return jsonify({
        "status": 200,
        "message": "Message sent at %s" % get_datetime(),
        "data": response
    })



