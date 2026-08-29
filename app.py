import random
import string
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permite que tu web en Netlify se comunique con este servidor

# Base de datos simulada en memoria
afiliados_db = {}


@app.route("/api/crear-afiliado", methods=["POST"])
def crear_afiliado():
  data = request.get_json()
  nombre = data.get("nombre", "").strip()

  if not nombre:
    return jsonify({"error": "El alias no puede estar vacío."}), 400

  link = f"/?ref={nombre}"
  return jsonify({"link": link})


@app.route("/api/registrar-compra", methods=["POST"])
def registrar_compra():
  # Generar clave de licencia Pro única
  letras = string.ascii_uppercase + string.digits
  b1 = "".join(random.choices(letras, k=4))
  b2 = "".join(random.choices(letras, k=4))
  b3 = "".join(random.choices(letras, k=4))
  licencia = f"ZETA-PRO-{b1}-{b2}-{b3}"

  return jsonify({"licencia": licencia})


if __name__ == "__main__":
  app.run(debug=True, port=5000)