from flask import Flask, request, jsonify
from src.controllers.auth_controller import AuthService
from src.routes.auth_route import AuthRoute

app = Flask(__name__)


@app.route('/login', methods=['POST'])
def login():
    login_route = AuthRoute.login_route()
    return login_route

if __name__ == '__main__':
    app.run(debug=True, port=6000)