import requests
import logging
from datetime import timedelta, datetime
from flask import jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash
import time


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


DATABASE_MANAGER_URL = 'http://127.0.0.1:5000'

class AuthService:
    def handle_login(self, username, password):
        """
        Authenticate user and return JWT token.
        """
        request_data = {
            "service": "AUTH-SERVICE",
            "table": "alunos",
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

                        # Criar token JWT
            additional_claims = {
                'iss': 'secrir',
                'aud': 'users',
                'iat': int(time.time())
            }

                    

            user_data = response.json()

            if 'data' not in user_data or not isinstance(user_data['data'], list) or not user_data['data']:
                logging.error(f"User {username} not found in database.")
                return {"msg": "Usuário não encontrado"}, 404
            
            user_info = user_data['data'][0]

            expires_in = timedelta(hours=1)
            token = create_access_token(identity={
                'username': user_info['username'],
                'identifier': user_info['id_aluno']
            }, additional_claims=additional_claims, expires_delta=expires_in)
                #return user_info
            logger.info(f"Usuário autenticado com sucesso.")
            return {'access_token': token}, 200

            #if not check_password_hash(user_info['password'], password):
            #   logger.error(f"Senha invalida para o user {username}.")
            # return {"msg": "Senha inválida"}, 401
        except Exception as e:
            logging.error(f"Error checking password for user {username}: {e}")
            return {"msg": "Erro ao verificar senha"}, 500