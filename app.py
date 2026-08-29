import os
import random
import string
from flask import Flask, jsonify, request
from flask_cors import CORS
import mercadopago

app = Flask(__name__)
CORS(app)  # Permite la conexión con Netlify

# Token de Mercado Pago (puedes usar uno de prueba o tu token de producción)
# Si estás probando, puedes dejar este de prueba o poner el tuyo entre comillas
ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN", "TEST-TU_ACCESS_TOKEN_AQUI")
sdk = mercadopago.SDK(ACCESS_TOKEN)


@app.route("/", methods=["GET"])
def home():
  return "El backend de ZetaBoost está activo 🚀"


@app.route("/api/crear-afiliado", methods=["POST"])
def crear_afiliado():
  data = request.get_json()
  nombre = data.get("nombre", "").strip()

  if not nombre:
    return jsonify({"error": "El alias no puede estar vacío."}), 400

  link = f"/?ref={nombre}"
  return jsonify({"link": link})


@app.route("/api/crear-pago-mp", methods=["POST"])
def crear_pago_mp():
  try:
    # Configuración del producto que se va a cobrar
    preference_data = {
        "items": [
            {
                "title": "ZetaBoost Pro - Licencia",
                "quantity": 1,
                "unit_price": 2.00,  # Podés cambiar el precio según tu moneda
            }
        ],
        "back_urls": {
            "success": "https://zetaaboost.netlify.app/",  # A dónde vuelve tras pagar con éxito
            "failure": "https://zetaaboost.netlify.app/",
            "pending": "https://zetaaboost.netlify.app/",
        },
        "auto_return": "approved",
    }

    preference_response = sdk.preference().create(preference_data)
    preference = preference_response["response"]

    # Devuelve el link oficial y seguro de Mercado Pago al frontend
    return jsonify({"init_point": preference["init_point"]})

  except Exception as e:
    return jsonify(
        {"error": "Error al conectar con Mercado Pago: " + str(e)}
    ), 500


if __name__ == "__main__":
  app.run(debug=True, port=5000)
