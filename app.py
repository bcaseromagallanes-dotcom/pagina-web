import random
import string
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permite que tu web en Netlify se comunique con este servidor

# Base de datos simulada en memoria (Guarda el alias y sus ventas totales)
# Ejemplo: {"progamer99": {"ventas": 3}}
afiliados_db = {}

def calcular_descuento_y_nivel(ventas):
    """Calcula el nivel de descuento según la cantidad de referidos."""
    if ventas >= 18:
        return {"descuentoActual": 50, "faltantesParaSiguiente": 0}  # Nivel Máximo (50%)
    elif ventas >= 8:
        return {"descuentoActual": 40, "faltantesParaSiguiente": 18 - ventas}  # Nivel Oro (40%)
    elif ventas >= 3:
        return {"descuentoActual": 30, "faltantesParaSiguiente": 8 - ventas}  # Nivel Plata (30%)
    else:
        return {"descuentoActual": 20, "faltantesParaSiguiente": 3 - ventas}  # Nivel Bronce (20%)


@app.route("/api/crear-afiliado", methods=["POST"])
def crear_afiliado():
    data = request.get_json()
    nombre = data.get("nombre", "").strip().lower()

    if not nombre:
        return jsonify({"error": "El alias no puede estar vacío."}), 400

    # Si el afiliado no existe todavía, lo creamos con 0 ventas
    if nombre not in afiliados_db:
        afiliados_db[nombre] = {"ventas": 0}

    ventas_totales = afiliados_db[nombre]["ventas"]
    info_nivel = calcular_descuento_y_nivel(ventas_totales)

    link = f"/?ref={nombre}"
    
    return jsonify({
        "link": link,
        "ventas": ventas_totales,
        "descuentoActual": info_nivel["descuentoActual"],
        "faltantesParaSiguiente": info_nivel["faltantesParaSiguiente"]
    })


@app.route("/api/registrar-compra", methods=["POST"])
def registrar_compra():
    data = request.get_json() or {}
    ref_code = data.get("ref", "").strip().lower()

    # Si el comprador entró con el código de un afiliado válido, le sumamos +1 venta
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
