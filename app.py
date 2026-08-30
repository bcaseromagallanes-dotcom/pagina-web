import random
import string
import time
import sqlite3
import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

DB_NAME = os.environ.get("DB_PATH", "database.db")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "ZETA2026ADMIN")

def query_db(query, args=(), one=False):
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        conn.commit()
        return (rv[0] if rv else None) if one else rv

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS usuarios (email TEXT PRIMARY KEY, password TEXT, alias TEXT, ventas INTEGER, hwid TEXT, licenciaActivada INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS licencias (codigo TEXT PRIMARY KEY, usada INTEGER)''')
        c.execute('''CREATE TABLE IF NOT EXISTS resenas (id INTEGER PRIMARY KEY AUTOINCREMENT, nombre TEXT, version TEXT, texto TEXT)''')
        conn.commit()

init_db()

ip_logs = {}

def check_rate_limit(ip, max_attempts=5, window=900):
    now = time.time()
    if ip not in ip_logs:
        ip_logs[ip] = []
    ip_logs[ip] = [t for t in ip_logs[ip] if now - t < window]
    if len(ip_logs[ip]) >= max_attempts:
        return False
    ip_logs[ip].append(now)
    return True

def calcular_descuento_y_nivel(ventas):
    if ventas >= 18: return {"descuentoActual": 50, "faltantesParaSiguiente": 0}
    elif ventas >= 8: return {"descuentoActual": 40, "faltantesParaSiguiente": 18 - ventas}
    elif ventas >= 3: return {"descuentoActual": 30, "faltantesParaSiguiente": 8 - ventas}
    else: return {"descuentoActual": 20, "faltantesParaSiguiente": 3 - ventas}

@app.route("/", methods=["GET"])
def home():
    return "ZetaBoost API funcionando correctamente!", 200

@app.route("/api/registro", methods=["POST"])
def registro():
    client_ip = request.remote_addr or "0.0.0.0"
    if not check_rate_limit(client_ip, max_attempts=5, window=900):
        return jsonify({"error": "Demasiados intentos. Esperá unos minutos."}), 429

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    confirm_password = data.get("confirmPassword", "").strip()
    hwid = data.get("hwid", "").strip()

    if not email or not password or not confirm_password:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400

    if password != confirm_password:
        return jsonify({"error": "Las contraseñas no coinciden."}), 400

    if query_db("SELECT email FROM usuarios WHERE email = ?", (email,), one=True):
        return jsonify({"error": "Este correo ya está registrado. Iniciá sesión."}), 400

    alias = email.split('@')[0].replace('.', '')
    password_hash = generate_password_hash(password)

    query_db("INSERT INTO usuarios (email, password, alias, ventas, hwid, licenciaActivada) VALUES (?, ?, ?, ?, ?, ?)",
             (email, password_hash, alias, 0, hwid if hwid else None, 0))

    info_nivel = calcular_descuento_y_nivel(0)
    return jsonify({
        "mensaje": "Cuenta creada con éxito",
        "email": email,
        "alias": alias,
        "ventas": 0,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={alias}",
        "licenciaActivada": False
    })

@app.route("/api/login", methods=["POST"])
def login():
    client_ip = request.remote_addr or "0.0.0.0"
    if not check_rate_limit(client_ip, max_attempts=10, window=600):
        return jsonify({"error": "Demasiados intentos fallidos. IP bloqueada temporalmente."}), 429

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    current_hwid = data.get("hwid", "").strip()

    if not email or not password:
        return jsonify({"error": "Ingresá tu correo y contraseña."}), 400

    user_data = query_db("SELECT * FROM usuarios WHERE email = ?", (email,), one=True)
    if not user_data or not check_password_hash(user_data["password"], password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401

    if not user_data["hwid"] and current_hwid:
        query_db("UPDATE usuarios SET hwid = ? WHERE email = ?", (current_hwid, email))
    elif current_hwid and user_data["hwid"] and user_data["hwid"] != current_hwid:
        return jsonify({"error": "Dispositivo no reconocido. Cuenta vinculada a otro PC.", "code": "HWID_MISMATCH"}), 403

    ventas = user_data["ventas"]
    info_nivel = calcular_descuento_y_nivel(ventas)

    return jsonify({
        "mensaje": "Sesión iniciada correctamente",
        "email": email,
        "alias": user_data["alias"],
        "ventas": ventas,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={user_data['alias']}",
        "licenciaActivada": bool(user_data["licenciaActivada"])
    })

@app.route("/api/verificar-ref/<alias>", methods=["GET"])
def verificar_ref(alias):
    alias = alias.strip().lower()
    user = query_db("SELECT ventas FROM usuarios WHERE alias = ?", (alias,), one=True)
    if user:
        info = calcular_descuento_y_nivel(user["ventas"])
        return jsonify({"valido": True, "descuento": info["descuentoActual"]})
    return jsonify({"valido": False, "descuento": 0})

@app.route("/api/admin/generar-licencia", methods=["GET"])
def generar_licencia():
    secret = request.args.get("secret")
    if secret != ADMIN_SECRET:
        return jsonify({"error": "Acceso denegado."}), 403

    letras = string.ascii_uppercase + string.digits
    licencia = f"ZETA-PRO-{''.join(random.choices(letras, k=4))}-{''.join(random.choices(letras, k=4))}-{''.join(random.choices(letras, k=4))}"
    
    query_db("INSERT INTO licencias (codigo, usada) VALUES (?, 0)", (licencia,))
    return jsonify({"licencia_generada": licencia, "estado": "Lista para usar"})

@app.route("/api/activar-licencia", methods=["POST"])
def activar_licencia():
    client_ip = request.remote_addr or "0.0.0.0"
    if not check_rate_limit(client_ip, max_attempts=5, window=600):
        return jsonify({"error": "Demasiados intentos. Bloqueo de 10 minutos."}), 429

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    licencia = data.get("licencia", "").strip()

    user = query_db("SELECT * FROM usuarios WHERE email = ?", (email,), one=True)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404

    lic = query_db("SELECT * FROM licencias WHERE codigo = ?", (licencia,), one=True)
    if not lic:
        return jsonify({"error": "Clave de licencia inválida."}), 400
    if lic["usada"] == 1:
        return jsonify({"error": "Esta clave ya fue utilizada por otro usuario."}), 400

    query_db("UPDATE licencias SET usada = 1 WHERE codigo = ?", (licencia,))
    query_db("UPDATE usuarios SET licenciaActivada = 1 WHERE email = ?", (email,))

    script_pro = "@echo off\ncls\necho ==================================\necho ZetaBoost Pro V4.5 Elite\necho ==================================\necho Aplicando optimizaciones de kernel...\ntimeout /t 2 >nul\necho Eliminando input lag...\ntimeout /t 2 >nul\necho Sistema optimizado!\npause"

    return jsonify({
        "exito": True, 
        "mensaje": "¡Licencia activada con éxito!",
        "script_pro": script_pro
    }), 200

@app.route("/api/reseñas", methods=["POST", "GET"])
def reseñas():
    if request.method == "POST":
        data = request.get_json() or {}
        texto = data.get("texto", "").strip()
        if not texto:
            return jsonify({"error": "El texto es obligatorio."}), 400
        
        nombre = data.get("nombre", "").strip() or "Comprador Anónimo"
        version = data.get("version", "").strip()
        
        query_db("INSERT INTO resenas (nombre, version, texto) VALUES (?, ?, ?)", (nombre, version, texto))
        return jsonify({"mensaje": "Reseña publicada con éxito"})
    
    rows = query_db("SELECT * FROM resenas ORDER BY id DESC")
    return jsonify([dict(ix) for ix in rows])

if __name__ == "__main__":
    app.run(debug=True, port=5000)
