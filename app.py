import random
import string
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permite la conexión con tu web en Netlify

# Base de datos simulada en memoria: 
# { "correo@example.com": {"password": "...", "alias": "usuario", "ventas": 0} }
afiliados_db = {}

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
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()
    confirm_password = data.get("confirmPassword", "").strip()

    if not email or not password or not confirm_password:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400

    if password != confirm_password:
        return jsonify({"error": "Las contraseñas no coinciden."}), 400

    if email in afiliados_db:
        return jsonify({"error": "Este correo ya está registrado. Iniciá sesión."}), 400

    # Generamos un alias automático para el link de referidos sacando lo que está antes del '@'
    alias = email.split('@')[0].replace('.', '')

    # Guardar en la base de datos
    afiliados_db[email] = {
        "password": password,
        "alias": alias,
        "ventas": 0
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
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "").strip()

    if not email or not password:
        return jsonify({"error": "Ingresá tu correo y contraseña."}), 400

    if email not in afiliados_db or afiliados_db[email]["password"] != password:
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401

    user_data = afiliados_db[email]
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
        # Por seguridad a veces se dice que se envió igual, pero acá avisamos si no existe
        return jsonify({"error": "No encontramos ninguna cuenta registrada con ese correo."}), 404

    # Aquí se simula el envío del correo de recuperación. 
    # (Si en el futuro querés enviar mails reales, acá podés integrar Flask-Mail con SMTP de Gmail)
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

    # Buscar si el código de referido coincide con algún alias de la base de datos
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
