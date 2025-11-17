# flask-linear-regression-api
Flask API with 2FA and ML
REST API with two-factor authentication and linear regression predictions.
Features

User registration with Argon2 password hashing
TOTP-based two-factor authentication
Password strength validation and breach detection
Linear regression model endpoint
Session-based authentication

Installation
bashpip install -r requirements.txt

On first run, the application will create the database and generate security configurations automatically.
API Endpoints
Authentication
POST /register
json{
  "username": "string",
  "password": "string"
}
Returns QR code for TOTP setup.
POST /login
json{
  "username": "string",
  "password": "string"
}
POST /verify_2fa
json{
  "code": "123456"
}
Machine Learning
GET/POST /api/model/linear (requires authentication)
?x=<value>
Returns prediction based on linear regression model.
GET /api/model/params
Returns model coefficients.
Utilities
POST /
ip=<IP_ADDRESS>
Ping utility.
GET /check_session
Check authentication status.
Security Notes

Change app.secret_key before deployment
Use HTTPS in production
Review password validation settings

Development
The application runs on http://127.0.0.1:5000 in debug mode by default.
Database
SQLite database (my2.db) with user table storing credentials and TOTP secrets.
