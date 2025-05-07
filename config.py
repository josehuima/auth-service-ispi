# auth_route.py

from flask import request, jsonify, url_for, Blueprint, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, decode_token
import requests
import logging
import check_password_hash

auth_bp = Blueprint('auth', __name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


DATABASE_MANAGER_URL = 'http://127.0.0.1:5000/'

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT token.
    """
    data = request.get_json()
    username = data.get['username'].strip()
    password = data.get['password'].strip()


    request_data = {
        "service": "AUTH-SERVICE",
        "table": "users",
        "limit": 1,
        "offset": 0,
        "filters": {
            "username": username
        }

    }

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(f"{DATABASE_MANAGER_URL}/query", json=request_data, headers=headers)
        response.raise_for_status()  # Retorna erro para código de status 4xx ou 5xx  

        user_data = response.json()

        if 'data' not in user_data or not isinstance(user_data['data'], list) or not user_data['data']:
            logger.error(f"User {username} not found in database.")
            return jsonify({"msg": "Usuário não encontrado"}), 404
        
        user_info = user_data['data'][0]

        #if not check_password_hash(user_info['password'], password):
         #   logger.error(f"Senha invalida para o user {username}.")
           # return jsonify({"msg": "Senha inválida"}), 401
    except Exception as e:
        logger.error(f"Error checking password for user {username}: {e}")
        return jsonify({"msg": "Erro ao verificar senha"}), 500
        