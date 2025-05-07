from flask import Flask, request, jsonify
from src.controllers.auth_controller import AuthService
from src.routes.auth_route import AuthRoute
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'sua_chave_supersecreta_aqui'  # valor seguro e privado
jwt = JWTManager(app)

@app.route('/login', methods=['POST'])
def login():
    login_route = AuthRoute.login_route()
    return login_route

if __name__ == '__main__':
    app.run(debug=True, port=6000)