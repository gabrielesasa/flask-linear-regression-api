from flask import Flask,request,jsonify,session,g,send_file
from sklearn.linear_model import LinearRegression
import numpy as np
import os
import subprocess
import ipaddress
import sqlite3
from argon2 import PasswordHasher
from dotenv import load_dotenv
import secrets
import hashlib
import requests,pyotp,io,qrcode

DATABASE = 'my2.db'
app = Flask(__name__)
app.secret_key = '1234'

def is_password_pwned(password):

    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    return suffix in res.text

def check_password(password):
    if len(password) < 8:
        return "La password deve avere almeno 8 caratteri"
    if not any(c.islower() for c in password):
        return "Deve contenere almeno una lettera minuscola"
    if not any(c.isupper() for c in password):
        return "Deve contenere almeno una lettera maiuscola"
    if not any(c.isdigit() for c in password):
        return "Deve contenere almeno un numero"
    if not any(c in "@$#%&!" for c in password):
        return "Deve contenere almeno un simbolo speciale (@$#%&!)"
    return True
    


def env_init():
    pepper = secrets.token_urlsafe(12)
    with open('.env','w') as f:
        f.write(f'PEPPER={pepper}\n')

def db_init():
    
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
                CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                otp TEXT NOT NULL)
                ''')
    conn.commit()
    conn.close()

def get_db():
    if not "db" in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db:
        db.close()


    

@app.route('/', methods = ['POST'])
def main():
    ip = request.form.get('ip')
    try:
        ipaddress.ip_address(ip)
        result = subprocess.run(['ping','-n','2',ip],capture_output = True,text= True,timeout = 10)
        if result.stderr:
            return "error"
        else:
           return result.stdout
    except Exception as e:
        return jsonify({'errore':"Ip non valido"}),400

@app.route('/register',methods = ['POST'])
def register():
    # E giusto che ad ogni funzione apro la connessione
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return "Missing username or password", 400
    # password_stautus = check_password(password)

   # if password_stautus != True:
    #    return password_stautus
    
  #  if is_password_pwned(password):
    #    return "This password isn't secure"
    db = get_db()
    cur = db.execute('SELECT * FROM user WHERE username = ?',(username,))
    exist_user = cur.fetchone()
    if exist_user:
        return "username is already taken"
    else:
        p_password = password + PEPPER
        hash = ph.hash(p_password)
        totp_secret = pyotp.random_base32()
        db.execute('''
                INSERT INTO user(username,password,otp)
                VALUES(?,?,?)''',(username,hash,totp_secret))
        db.commit()

        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="MyFlaskApp")
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        return send_file(buf, mimetype="image/png")
        


@app.route('/login',methods= ['GET','POST'])
def login():
    if request.method == 'GET':
        username = request.args.get('username')
        password = request.args.get('password')
    
    elif request.content_type == 'application/x-www-form-urlencoded':
        username = request.form.get('username')
        password = request.form.get('password')
        
    elif request.is_json:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password') 

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}),400
    
    db = get_db()
    cursor = db.execute('SELECT password FROM user WHERE username = ?', (username,))
    tpassword = cursor.fetchone()[0]
    p_password = password + PEPPER
    if ph.verify(tpassword,p_password):
        session['username'] = username
        return jsonify({'message': 'Password correct, enter your TOTP code'}),200
    else:
        return jsonify({'error': 'Invalid credentials'}),401

@app.route('/api/model/linear',methods= ['GET','POST'])
def find_y():
    if 'authenticated' in session:
        if request.method == 'GET':
            x = int(request.args.get('x'))
        elif request.method == 'POST':
            x = int(request.form.get('x'))
        y = model.predict([[x]]).tolist()
        return jsonify({'x':x,'y': y})
    else:
        return jsonify({'error': 'Invalid session'}),401

@app.route('/check_session', methods=['GET'])
def check_session():
    if 'username' in session:
        return jsonify({'logged_in': True, 'user': session['username']})
    return jsonify({'logged_in': False})

@app.route("/verify_2fa", methods=["POST"])
def verify_2fa():
    data = request.json
    code = data.get("code")
    username = session.get("username")

    if not username:
        return jsonify({"error": "Login necessario"}), 401
    db = get_db()
    cur = db.execute('SELECT otp FROM user WHERE username = ?',(username,))
    otp = cur.fetchone()[0]
    totp = pyotp.TOTP(otp)
    if totp.verify(code):
        session["authenticated"] = True
        return jsonify({"message": "Login completato per {username} "}), 200
    else:
        return jsonify({"error": "Codice TOTP errato"}), 401

@app.route('/api/model/params')
def show_params():
    a = float(model.intercept_)
    b = model.coef_.tolist()
    return jsonify({'a':a,'b': b})
 
    
if __name__ == '__main__':
    result = load_dotenv() 
    PEPPER = os.getenv('PEPPER')
    if not os.path.exists(DATABASE):
        db_init()
    if not os.path.exists('.env'):
        env_init()
    ph = PasswordHasher()
    size=np.array([50,70,100,120,124]).reshape(-1,1)
    price = np.array([100,120,130,140,150])
    model = LinearRegression()
    model.fit(size,price)
    app.run(debug=True)