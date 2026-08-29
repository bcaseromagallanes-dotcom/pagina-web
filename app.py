import random
import string
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permite la conexión con tu web en Netlify

# Base de datos simulada en memoria con cuentas: { "alias": {"password": "...", "ventas": 0} }
afiliados_db = {}

def calcular_descuento_y_nivel(ventas):
    """Calcula el nivel de descuento según la cantidad de ventas."""
    if ventas >= 18:
        return {"descuentoActual": 50, "faltantesParaSiguiente": 0}  # Nivel Máximo (50%)
    elif ventas >= 8:
        return {"descuentoActual": 40, "faltantesParaSiguiente": 18 - ventas}  # Nivel Oro (40%)
    elif ventas >= 3:
        return {"descuentoActual": 30, "faltantesParaSiguiente": 8 - ventas}  # Nivel Plata (30%)
    else:
        return {"descuentoActual": 20, "faltantesParaSiguiente": 3 - ventas}  # Nivel Bronce (20%)


@app.route("/api/registro", methods=["POST"])
def registro():
    data = request.get_json() or {}
    nombre = data.get("nombre", "").strip().lower()
    password = data.get("password", "").strip()

    if not nombre or not password:
        return jsonify({"error": "El alias y la contraseña son obligatorios."}), 400

    if nombre in afiliados_db:
        return jsonify({"error": "Ese alias ya está registrado. Por favor, iniciá sesión."}), 400

    # Crear la cuenta del afiliado
    afiliados_db[nombre] = {"password": password, "ventas": 0}
    
    info_nivel = calcular_descuento_y_nivel(0)
    return jsonify({
        "mensaje": "Cuenta creada con éxito",
        "nombre": nombre,
        "ventas": 0,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={nombre}"
    })


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    nombre = data.get("nombre", "").strip().lower()
    password = data.get("password", "").strip()

    if not nombre or not password:
        return jsonify({"error": "Completá todos los campos para iniciar sesión."}), 400

    if nombre not in afiliados_db or afiliados_db[nombre]["password"] != password:
        return jsonify({"error": "Alias o contraseña incorrectos."}), 401

    ventas = afiliados_db[nombre]["ventas"]
    info_nivel = calcular_descuento_y_nivel(ventas)

    return jsonify({
        "mensaje": "Sesión iniciada correctamente",
        "nombre": nombre,
        "ventas": ventas,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"],
        "link": f"/?ref={nombre}"
    })


@app.route("/api/verificar-ref/<nombre>", methods=["GET"])
def verificar_ref(nombre):
    """Permite consultar el descuento actual de un cupón en la tienda."""
    nombre = nombre.strip().lower()
    if nombre in afiliados_db:
        ventas = afiliados_db[nombre]["ventas"]
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

    if ref_code in afiliados_db:
        afiliados_db[ref_code]["ventas"] += 1

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
