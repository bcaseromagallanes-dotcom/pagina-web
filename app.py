import random
import string
import time
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)  # Permite la conexión con tu web en Netlify

# Base de datos simulada en memoria: 
# { "correo@example.com": {"password": "hash...", "alias": "usuario", "ventas": 0, "hwid": "..."} }
afiliados_db = {}

# Control de Rate Limiting por IP en memoria (anti-spam / multicuentas)
ip_logs = {}

def check_rate_limit(ip, max_attempts=5, window=900):
    """Permite máximo 5 intentos cada 15 minutos (900 segundos) por IP."""
    now = time.time()
    if ip not in ip_logs:
        ip_logs[ip] = []
    
    # Limpiar registros fuera de la ventana de tiempo
    ip_logs[ip] = [t for t in ip_logs[ip] if now - t < window]
    
    if len(ip_logs[ip]) >= max_attempts:
        return False
    
    ip_logs[ip].append(now)
    return True

def calcular_descuento_y_nivel(ventas):
    """Calcula el nivel de descuento según la cantidad de ventas."""
    if ventas >= 18:
        return {"descuentoActual": 50, "faltantesParaSiguiente": 0}
    elif ventas >= 8:
        return {"descuentoActual": 40, "faltantesParaSiguiente": 18 - ventas}
    elif ventas >= 3:
        return {"descuentoActual": 30, "faltantesParaSiguiente": 8 - ventas}
    else:
        return {"descuentoActual": 20, "faltantesParaSiguiente": 3 - ventas}


@app.route("/api/registro", methods=["POST"])
def registro():
    client_ip = request.remote_addr or "0.0.0.0"
    
    # Aplicar Rate Limiting al registrarse
    if not check_rate_limit(client_ip, max_attempts=5, window=900):
        return jsonify({"error": "Demasiados intentos de registro desde esta IP. Esperá unos minutos."}), 429

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    confirm_password = data.get("confirmPassword", "").strip()
    hwid = data.get("hwid", "").strip() # Recibe el HWID opcional u obligatorio desde el cliente

    if not email or not password or not confirm_password:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400

    if password != confirm_password:
        return jsonify({"error": "Las contraseñas no coinciden."}), 400

    # 1 cuenta por email (Validación estricta)
    if email in afiliados_db:
        return jsonify({"error": "Este correo ya está registrado. Iniciá sesión."}), 400

    # Generamos un alias automático para el link de referidos
    alias = email.split('@')[0].replace('.', '')

    # Encriptar la contraseña de forma segura (Hash) en lugar de texto plano
    password_hash = generate_password_hash(password)

    # Guardar en la base de datos simulada con soporte para HWID
    afiliados_db[email] = {
        "password": password_hash,
        "alias": alias,
        "ventas": 0,
        "hwid": hwid if hwid else None
    }

    info_nivel = calcular_descuento_y_nivel(0)
    return jsonify({
        "mensaje": "Cuenta creada con éxito",
        "email": email,
        "alias": alias,
        "ventas": 0,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={alias}"
    })


@app.route("/api/login", methods=["POST"])
def login():
    client_ip = request.remote_addr or "0.0.0.0"
    
    # Aplicar Rate Limiting en el login para evitar ataques de fuerza bruta
    if not check_rate_limit(client_ip, max_attempts=10, window=600):
        return jsonify({"error": "Demasiados intentos fallidos. IP bloqueada temporalmente."}), 429

    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    current_hwid = data.get("hwid", "").strip()

    if not email or not password:
        return jsonify({"error": "Ingresá tu correo y contraseña."}), 400

    if email not in afiliados_db:
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401

    user_data = afiliados_db[email]

    # Verificar la contraseña cifrada mediante hash
    if not check_password_hash(user_data["password"], password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401

    # Protección Anti-Compartir (Vinculación de Hardware - HWID)
    if not user_data["hwid"]:
        # Si el usuario aún no tenía HWID registrado, se lo vinculamos en el primer acceso
        if current_hwid:
            user_data["hwid"] = current_hwid
    elif current_hwid and user_data["hwid"] != current_hwid:
        # Si el HWID actual no coincide con el registrado, se bloquea por intento de compartir cuenta
        return jsonify({
            "error": "Dispositivo no reconocido. Esta cuenta ya está vinculada a otro ordenador (Protección Anti-Compartir).",
            "code": "HWID_MISMATCH"
        }, 403)

    ventas = user_data["ventas"]
    info_nivel = calcular_descuento_y_nivel(ventas)

    return jsonify({
        "mensaje": "Sesión iniciada correctamente",
        "email": email,
        "alias": user_data["alias"],
        "ventas": ventas,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={user_data['alias']}"
    })


@app.route("/api/recuperar-password", methods=["POST"])
def recuperar_password():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Ingresá tu correo electrónico."}), 400

    if email not in afiliados_db:
        return jsonify({"error": "No encontramos ninguna cuenta registrada con ese correo."}), 404

    return jsonify({
        "success": True,
        "mensaje": f"Se han enviado las instrucciones de recuperación al correo: {email}"
    })


@app.route("/api/verificar-ref/<alias>", methods=["GET"])
def verificar_ref(alias):
    """Permite consultar el descuento actual de un cupón mediante su alias."""
    alias = alias.strip().lower()
    for email, data in afiliados_db.items():
        if data["alias"] == alias:
            ventas = data["ventas"]
            info = calcular_descuento_y_nivel(ventas)
            return jsonify({
                "valido": True,
                "descuento": info["descuentoActual"]
            })
    return jsonify({"valido": False, "descuento": 0})


@app.route("/api/registrar-compra", methods=["POST"])
def registrar_compra():
    data = request.get_json() or {}
    ref_code = data.get("ref", "").strip().lower()

    # Buscar si el código de referido coincide con algún alias
    for email, user_data in afiliados_db.items():
        if user_data["alias"] == ref_code:
            user_data["ventas"] += 1
            break

    # Generar clave de licencia Pro única
    letras = string.ascii_uppercase + string.digits
    b1 = "".join(random.choices(letras, k=4))
    b2 = "".join(random.choices(letras, k=4))
    b3 = "".join(random.choices(letras, k=4))
    licencia = f"ZETA-PRO-{b1}-{b2}-{b3}"

    return jsonify({
        "licencia": licencia,
        "mensaje": "Compra procesada correctamente y referido contabilizado."
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
