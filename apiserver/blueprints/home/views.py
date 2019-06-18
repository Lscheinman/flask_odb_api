from flask import jsonify, Blueprint
from apiserver.blueprints.home.models import ODB

home = Blueprint('home', __name__)
odbserver = ODB()
odbserver.open_db()


@home.route('/', methods=['GET'])
def index():

    return jsonify({
        "status": 200,
        "message": "Welcome. Basic stats of the endpoint database",
        "data": odbserver.get_db_stats()
    })


@home.route('/snapshot', methods=['GET'])
def get_snapshot():

    return jsonify({
        "status": 200,
        "message": "Sample data from the file system",
        "data": odbserver.get_data()
    })
