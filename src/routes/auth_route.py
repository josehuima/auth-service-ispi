from flask import request, jsonify
from src.controllers.auth_controller import AuthService

class AuthRoute:
    def login_route():
        """
        Rota para login.
        """
        data = request.get_json()
        username = data.get('username').strip()
        password = data.get('password').strip()

        auth_service = AuthService()
        response = auth_service.handle_login(username, password)

        if isinstance(response, tuple):
            return jsonify(response[0]), response[1]

        return jsonify(response), 200
    
    def reset_password_route():
        """
        Rota para resetar password.
        """
        data = request.get_json()
        username = data.get('username').strip()
        new_password = data.get('new_password').strip()

        auth_service = AuthService()
        response = auth_service.handle_reset_password(username, new_password)

        if isinstance(response, tuple):
            return jsonify(response[0]), response[1]

        return jsonify(response), 200
    