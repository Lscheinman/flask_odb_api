from flask import jsonify, Blueprint, request
from apiserver.blueprints.users.models import userDB

users = Blueprint('users', __name__)
odbserver = userDB()
odbserver.open_db()


@users.route('/users', methods=['GET'])
def index():

    return jsonify({
        "status": 200,
        "message": "Welcome. Basic stats of the endpoint database",
        "data": odbserver.get_db_stats()
    })


@users.route('/users/snapshot', methods=['GET', 'POST'])
def get_snapshot():

    if request.method == "POST":
        auth = odbserver.auth_user(request.headers['Authorization'])
        if auth:
            return jsonify(auth)
        else:
            return jsonify({
                "status": 200,
                "message": "Sample data from the file system",
                "data": odbserver.get_data()
            })
    else:
        return jsonify({
            "status": 200,
            "message": "Sample data from the file system",
            "data": odbserver.get_data()
        })


@users.route('/users/delete', methods=['POST'])
def delete():

    auth = odbserver.auth_user(request.headers['Authorization'])
    if auth:
        return jsonify(auth)
    else:
        results = odbserver.delete_user(request)
        if results['data']:
            return jsonify({
                "status": 201,
                "message": results['message'],
                "node": results['data']
            })
        else:
            return jsonify({
                "status": 409,
                "message": results['message']
            })


@users.route('/users/create', methods=['POST'])
def create():

    results = odbserver.create_user(request.form.to_dict(flat=True))
    if results:
        return jsonify({
            "status": 201,
            "message": results['message'],
            "node": results['data']
        })
    else:
        return jsonify({
            "status": 409,
            "message": "User exists"
        })


@users.route('/users/login', methods=['POST'])
def login():

    auth = odbserver.login(request)
    if auth['session']:
        return jsonify({
            "status": 200,
            "message": "User authenticated",
            "token": auth['token'],
            "sessionId": auth['session']
        })
    else:
        return jsonify({
            "status": 204,
            "message": auth['message']
        })


@users.route('/users/logout', methods=['POST'])
def logout():

    auth = odbserver.auth_user(request.headers['Authorization'])
    if auth:
        return jsonify(auth)
    else:
        auth = odbserver.logout(request)
        if auth:
            return jsonify({
                "status": 200,
                "message": auth
            })
        else:
            return jsonify({
                "status": 204,
                "message": auth
            })

@users.route('/users/get', methods=['POST'])
def get():

    auth = odbserver.auth_user(request.headers['Authorization'])
    if auth:
        return jsonify(auth)
    else:
        auth = odbserver.get_activity(request)
        if auth["data"]:
            return jsonify({
                "status": 200,
                "message": auth['message'],
                "data": auth["data"]
            })
        else:
            return jsonify({
                "status": 204,
                "message": auth["message"]
            })

@users.route('/users/message', methods=['POST'])
def message():

    auth = odbserver.auth_user(request.headers['Authorization'])
    if auth:
        return jsonify(auth)
    else:
        auth = odbserver.send_message(request)
        if auth["data"]:
            return jsonify({
                "status": 200,
                "message": auth['message'],
                "data": auth["data"]
            })
        else:
            return jsonify({
                "status": 204,
                "message": auth["message"]
            })

