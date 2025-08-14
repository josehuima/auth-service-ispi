import requests
import logging
from datetime import timedelta
from flask_jwt_extended import create_access_token
import hashlib
import time

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DATABASE_MANAGER_URL = 'http://127.0.0.1:5000'


class AuthService:
    def handle_login(self, username: int, password: str):
        """
        Authenticate user and return JWT token.
        """
        request_data = {
            "service": "AUTH-SERVICE",
            "table": "T_Aluno",
            "limit": 1,
            "offset": 0,
            "filters": {
                "numero": username
            }
        }

        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{DATABASE_MANAGER_URL}/query", json=request_data, headers=headers)
            logger.debug(f"DEBUG status: {response.status_code}")
            logger.debug(f"DEBUG body: {response.text}")
            response.raise_for_status()

            additional_claims = {
                'iss': 'secrir',
                'aud': 'users',
                'iat': int(time.time())
            }

            user_data = response.json()

            if 'data' not in user_data or not isinstance(user_data['data'], list) or not user_data['data']:
                logger.error(f"User {username} not found in database.")
                return {"msg": "Usuário não encontrado"}, 404

            user_info = user_data['data'][0]

            # Verifica senha usando MD5
            stored_hash = (user_info.get('PasswordWEB') or user_info.get('password') or "").lower()
            calc_hash = hashlib.md5((password + str(username)).encode("utf-8")).hexdigest()

            if calc_hash != stored_hash:
                logger.error(f"Senha inválida para o user {username}.")
                return {"msg": "Senha inválida"}, 401

            expires_in = timedelta(hours=1)
            token = create_access_token(
                identity={
                    'username': user_info['numero'],
                    'identifier': user_info['numero']
                },
                additional_claims=additional_claims,
                expires_delta=expires_in
            )

            logger.info(f"Usuário autenticado com sucesso.")
            return {'access_token': token}, 200

        except Exception as e:
            logger.error(f"Error checking password for user {username}: {e}")
            return {"msg": "Erro ao verificar senha"}, 500

    def handle_reset_password(self, username, new_password):
        """
        Resetar password.
        """
        request_data = {
            "service": "AUTH-SERVICE",
            "table": "T_Aluno",
            "limit": 1,
            "offset": 0,
            "filters": {
                "numero": username
            }
        }

        try:
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{DATABASE_MANAGER_URL}/query", json=request_data, headers=headers)
            response.raise_for_status()  # Retorna erro para código de status 4xx ou 5xx

            user_data = response.json()

            if 'data' not in user_data or not isinstance(user_data['data'], list) or not user_data['data']:
                logging.error(f"User {username} not found in database.")
                return {"msg": "Usuário não encontrado"}, 404

            user_info = user_data['data'][0]

            # lógica para atualizar a senha no banco de dados
            new_request_data = {
                "service": "AUTH-SERVICE",
                "table": "alunos",
                "data": {
                    "numero": username,
                    "PasswordWEB": new_password
                }
            }

            requests.post(
                f"{DATABASE_MANAGER_URL}/update-password",
                json=new_request_data,
                headers=headers
            )

            logger.info(f"Senha do usuário {username} redefinida com sucesso.")
            return {"msg": "Senha redefinida com sucesso"}, 200

        except Exception as e:
            logging.error(f"Error resetting password for user {username}: {e}")
            return {"msg": "Erro ao redefinir senha"}, 500
