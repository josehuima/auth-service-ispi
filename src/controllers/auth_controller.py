import requests
import logging

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

            user_data = response.json()

            if 'data' not in user_data or not isinstance(user_data['data'], list) or not user_data['data']:
                logging.error(f"User {username} not found in database.")
                return {"msg": "Usuário não encontrado"}, 404
            
            user_info = user_data['data'][0]
            return user_info

            #if not check_password_hash(user_info['password'], password):
             #   logger.error(f"Senha invalida para o user {username}.")
               # return {"msg": "Senha inválida"}, 401
        except Exception as e:
            logging.error(f"Error checking password for user {username}: {e}")
            return {"msg": "Erro ao verificar senha"}, 500