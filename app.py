import os
import secrets
import hashlib
import re
import time
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# -------------------------
# Configuración segura
# -------------------------
IS_PROD = os.environ.get("RENDER", "").lower() == "true" or bool(os.environ.get("RENDER_EXTERNAL_URL"))
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(48)
    # En producción esto hace que las sesiones se invaliden al reiniciar.
    # Configurá SECRET_KEY en Render para que sea persistente.

ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET and IS_PROD:
    # No arrancamos en producción con un secreto admin hardcodeado.
    raise RuntimeError("Falta la variable de entorno ADMIN_SECRET en Render.")
ADMIN_SECRET = ADMIN_SECRET or secrets.token_urlsafe(32)

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///database.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

FRONTEND_ORIGINS = [x.strip().rstrip("/") for x in os.environ.get("FRONTEND_ORIGINS", "http://localhost:8888,http://localhost:3000").split(",") if x.strip()]
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true" if IS_PROD else "false").lower() == "true"

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=DATABASE_URL,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"check_same_thread": False}},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE="None" if COOKIE_SECURE else "Lax",
    MAX_CONTENT_LENGTH=1024 * 1024,
)

db = SQLAlchemy(app)
CORS(
    app,
    resources={r"/api/*": {"origins": FRONTEND_ORIGINS}},
    supports_credentials=True,
)

# -------------------------
# Modelos
# -------------------------
class User(db.Model):
    __tablename__ = "usuarios"

    email = db.Column(db.String(255), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    alias = db.Column(db.String(80), unique=True, nullable=False, index=True)
    ventas = db.Column(db.Integer, nullable=False, default=0)
    hwid_hash = db.Column(db.String(64), nullable=True)
    licencia_activada = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: utc_now())


class License(db.Model):
    __tablename__ = "licencias"

    codigo = db.Column(db.String(64), primary_key=True)
    status = db.Column(db.String(16), nullable=False, default="spare", index=True)  # spare/bound/revoked
    user_email = db.Column(db.String(255), db.ForeignKey("usuarios.email"), nullable=True, index=True)
    hwid_hash = db.Column(db.String(64), nullable=True)
    tier = db.Column(db.String(16), nullable=False, default="PRO")
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: utc_now())
    bound_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_seen_at = db.Column(db.DateTime(timezone=True), nullable=True)


class Review(db.Model):
    __tablename__ = "resenas"

    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    version = db.Column(db.String(40), nullable=True)
    texto = db.Column(db.String(1000), nullable=False)
    user_email = db.Column(db.String(255), db.ForeignKey("usuarios.email"), nullable=True, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: utc_now())


class CSRFStore(db.Model):
    __tablename__ = "csrf_tokens"

    user_email = db.Column(db.String(255), primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: utc_now())


with app.app_context():
    db.create_all()

# -------------------------
# Rate limit básico
# -------------------------
RATE_LOGS = {}


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0").split(",")[0].strip()


def rate_limit(bucket, max_attempts=8, window_seconds=600):
    now = time.time()
    key = f"{bucket}:{client_ip()}"
    events = RATE_LOGS.get(key, [])
    events = [t for t in events if now - t < window_seconds]
    if len(events) >= max_attempts:
        RATE_LOGS[key] = events
        return False
    events.append(now)
    RATE_LOGS[key] = events
    return True


def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode("utf-8")).hexdigest()


def clean_email(email: str) -> str:
    return email.strip().lower()


def clean_alias(alias: str) -> str:
    alias = re.sub(r"[^a-zA-Z0-9_-]", "", alias.strip().lower())
    return alias[:60]


def make_alias(email: str) -> str:
    base = clean_alias(email.split("@", 1)[0]) or "usuario"
    alias = base
    n = 2
    while User.query.filter_by(alias=alias).first() is not None:
        alias = f"{base}{n}"
        n += 1
    return alias


def calcular_descuento_y_nivel(ventas: int):
    if ventas >= 18:
        return {"descuentoActual": 50, "faltantesParaSiguiente": 0}
    if ventas >= 8:
        return {"descuentoActual": 40, "faltantesParaSiguiente": 18 - ventas}
    if ventas >= 3:
        return {"descuentoActual": 30, "faltantesParaSiguiente": 8 - ventas}
    return {"descuentoActual": 20, "faltantesParaSiguiente": 3 - ventas}


def user_payload(user: User):
    nivel = calcular_descuento_y_nivel(user.ventas)
    active_license = License.query.filter_by(user_email=user.email, status="bound").order_by(License.created_at.desc()).first()
    expires_at = active_license.expires_at.isoformat() if active_license and active_license.expires_at else None
    return {
        "email": user.email,
        "alias": user.alias,
        "ventas": user.ventas,
        "descuentoActual": nivel["descuentoActual"],
        "faltantesParaSiguiente": nivel["faltantesParaSiguiente"],
        "link": f"/?ref={user.alias}",
        "licenciaActivada": bool(user.licencia_activada),
        "hwidVinculado": bool(user.hwid_hash),
        "licencia": {
            "activa": bool(active_license),
            "tier": active_license.tier if active_license else None,
            "vence": expires_at,
            "status": active_license.status if active_license else None,
        },
    }


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        email = session.get("email")
        if not email:
            return jsonify({"error": "Sesión requerida."}), 401
        user = db.session.get(User, email)
        if not user:
            session.clear()
            return jsonify({"error": "Sesión inválida."}), 401
        return fn(user, *args, **kwargs)
    return wrapper


def issue_csrf(user_email: str) -> str:
    token = secrets.token_urlsafe(32)
    row = db.session.get(CSRFStore, user_email)
    hashed = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if row:
        row.token_hash = hashed
        row.created_at = utc_now()
    else:
        db.session.add(CSRFStore(user_email=user_email, token_hash=hashed))
    db.session.commit()
    return token


def require_csrf():
    email = session.get("email")
    sent = request.headers.get("X-CSRF-Token", "")
    if not email or not sent:
        return False
    row = db.session.get(CSRFStore, email)
    if not row:
        return False
    return secrets.compare_digest(row.token_hash, hashlib.sha256(sent.encode("utf-8")).hexdigest())


def require_admin():
    provided = request.headers.get("X-Admin-Secret", "")
    return bool(provided) and secrets.compare_digest(provided, ADMIN_SECRET)


def utc_now():
    return datetime.now(timezone.utc)


def license_is_valid(lic: License) -> bool:
    if not lic or lic.status != "bound":
        return False
    if lic.expires_at is None:
        return True
    expiry = lic.expires_at
    # SQLite puede devolver datetimes sin tzinfo aunque el modelo use timezone=True.
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > utc_now()

# -------------------------
# Rutas públicas
# -------------------------
@app.get("/")
def home():
    return jsonify({"ok": True, "service": "ZetaBoost API", "version": "2.0"})


@app.get("/api/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"ok": True})
    except Exception:
        return jsonify({"ok": False}), 503


@app.post("/api/registro")
def registro():
    if not rate_limit("registro", max_attempts=5, window_seconds=900):
        return jsonify({"error": "Demasiados intentos. Esperá unos minutos."}), 429

    data = request.get_json(silent=True) or {}
    email = clean_email(str(data.get("email", "")))
    password = str(data.get("password", ""))
    confirm_password = str(data.get("confirmPassword", ""))

    if not email or not password or not confirm_password:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400
    if len(email) > 255 or "@" not in email:
        return jsonify({"error": "Ingresá un correo válido."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "La contraseña debe tener entre 8 y 128 caracteres."}), 400
    if password != confirm_password:
        return jsonify({"error": "Las contraseñas no coinciden."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Este correo ya está registrado. Iniciá sesión."}), 400

    user = User(email=email, password_hash=generate_password_hash(password), alias=make_alias(email), ventas=0)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "No se pudo crear la cuenta. Probá nuevamente."}), 409

    session.clear()
    session["email"] = user.email
    csrf = issue_csrf(user.email)
    return jsonify({"mensaje": "Cuenta creada con éxito", "csrfToken": csrf, **user_payload(user)}), 201


@app.post("/api/login")
def login():
    if not rate_limit("login", max_attempts=10, window_seconds=600):
        return jsonify({"error": "Demasiados intentos. Probá más tarde."}), 429

    data = request.get_json(silent=True) or {}
    email = clean_email(str(data.get("email", "")))
    password = str(data.get("password", ""))
    if not email or not password:
        return jsonify({"error": "Ingresá tu correo y contraseña."}), 400

    user = db.session.get(User, email)
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Correo o contraseña incorrectos."}), 401

    session.clear()
    session["email"] = user.email
    csrf = issue_csrf(user.email)
    return jsonify({"mensaje": "Sesión iniciada correctamente", "csrfToken": csrf, **user_payload(user)})


@app.post("/api/logout")
@require_auth
def logout(user):
    if not require_csrf():
        return jsonify({"error": "CSRF inválido."}), 403
    session.clear()
    return jsonify({"mensaje": "Sesión cerrada."})


@app.get("/api/session")
def current_session():
    email = session.get("email")
    if not email:
        return jsonify({"autenticado": False})
    user = db.session.get(User, email)
    if not user:
        session.clear()
        return jsonify({"autenticado": False})
    return jsonify({"autenticado": True, **user_payload(user)})


@app.get("/api/verificar-ref/<alias>")
def verificar_ref(alias):
    alias = clean_alias(alias)
    user = User.query.filter(func.lower(User.alias) == alias).first()
    if not user:
        return jsonify({"valido": False, "descuento": 0})
    info = calcular_descuento_y_nivel(user.ventas)
    return jsonify({"valido": True, "descuento": info["descuentoActual"]})


@app.get("/api/reseñas")
def listar_resenas():
    rows = Review.query.order_by(Review.id.desc()).limit(100).all()
    return jsonify([
        {
            "id": r.id,
            "nombre": r.nombre,
            "version": r.version or "",
            "texto": r.texto,
            "createdAt": r.created_at.isoformat(),
        }
        for r in rows
    ])


@app.post("/api/reseñas")
@require_auth
def guardar_resena(user):
    if not require_csrf():
        return jsonify({"error": "CSRF inválido."}), 403
    if not rate_limit("reviews", max_attempts=3, window_seconds=3600):
        return jsonify({"error": "Demasiadas reseñas. Probá más tarde."}), 429

    # Solo compradores verificados pueden publicar.
    lic = License.query.filter_by(user_email=user.email, status="bound").first()
    if not lic or not license_is_valid(lic):
        return jsonify({"error": "Necesitás una licencia Pro activa para publicar una reseña verificada."}), 403

    data = request.get_json(silent=True) or {}
    texto = str(data.get("texto", "")).strip()
    version = str(data.get("version", "")).strip()[:40]
    if not texto:
        return jsonify({"error": "El texto es obligatorio."}), 400
    if len(texto) > 1000:
        return jsonify({"error": "La reseña no puede superar 1000 caracteres."}), 400

    review = Review(nombre=user.alias, version=version, texto=texto, user_email=user.email)
    db.session.add(review)
    db.session.commit()
    return jsonify({"mensaje": "Reseña publicada con éxito"}), 201

# -------------------------
# Licencias / anti-compartición
# -------------------------
@app.post("/api/activar-licencia")
@require_auth
def activar_licencia(user):
    if not require_csrf():
        return jsonify({"error": "CSRF inválido."}), 403
    if not rate_limit("activate", max_attempts=5, window_seconds=600):
        return jsonify({"error": "Demasiados intentos. Bloqueo temporal."}), 429

    data = request.get_json(silent=True) or {}
    licencia_codigo = str(data.get("licencia", "")).strip().upper()
    hwid = str(data.get("hwid", "")).strip()
    if not licencia_codigo or not hwid:
        return jsonify({"error": "Licencia y HWID son obligatorios."}), 400
    if len(hwid) < 8 or len(hwid) > 512:
        return jsonify({"error": "HWID inválido."}), 400

    hwid_digest = hash_hwid(hwid)
    lic = License.query.filter_by(codigo=licencia_codigo).with_for_update().first()
    if not lic:
        return jsonify({"error": "Clave de licencia inválida."}), 400
    if lic.status == "revoked":
        return jsonify({"error": "Esta clave fue revocada."}), 400

    # Una cuenta = un dispositivo. Una licencia = una cuenta + un dispositivo.
    if user.hwid_hash and not secrets.compare_digest(user.hwid_hash, hwid_digest):
        return jsonify({
            "error": "Dispositivo no reconocido. La cuenta ya está vinculada a otro PC.",
            "code": "HWID_MISMATCH",
        }), 403

    if lic.status == "bound":
        if lic.user_email != user.email or not lic.hwid_hash or not secrets.compare_digest(lic.hwid_hash, hwid_digest):
            return jsonify({"error": "Esta licencia ya está vinculada a otra cuenta o dispositivo."}), 409
        return jsonify({"error": "La licencia ya estaba activada en esta cuenta.", **user_payload(user)})

    # Evita que una cuenta tenga múltiples licencias simultáneas por accidente.
    existing = License.query.filter_by(user_email=user.email, status="bound").first()
    if existing and license_is_valid(existing):
        return jsonify({"error": "Tu cuenta ya tiene una licencia Pro activa."}), 409

    now = utc_now()
    lic.status = "bound"
    lic.user_email = user.email
    lic.hwid_hash = hwid_digest
    lic.bound_at = now
    lic.last_seen_at = now
    user.hwid_hash = hwid_digest
    user.licencia_activada = True
    db.session.commit()

    # NO enviamos el script .bat desde el servidor. El archivo Pro debe consultar
    # /api/license/validate antes de ejecutar optimizaciones.
    return jsonify({
        "exito": True,
        "mensaje": "¡Licencia activada y vinculada a este dispositivo!",
        "license": {
            "tier": lic.tier,
            "vence": lic.expires_at.isoformat() if lic.expires_at else None,
            "status": lic.status,
        },
        **user_payload(user),
    })


@app.post("/api/license/validate")
@require_auth
def validate_license(user):
    if not require_csrf():
        return jsonify({"valid": False, "error": "CSRF inválido."}), 403
    data = request.get_json(silent=True) or {}
    hwid = str(data.get("hwid", "")).strip()
    if not hwid or not user.hwid_hash:
        return jsonify({"valid": False, "error": "Dispositivo no vinculado."}), 403

    digest = hash_hwid(hwid)
    if not secrets.compare_digest(user.hwid_hash, digest):
        return jsonify({"valid": False, "code": "HWID_MISMATCH", "error": "Dispositivo no autorizado."}), 403

    lic = License.query.filter_by(user_email=user.email, status="bound").order_by(License.created_at.desc()).first()
    if not lic or not lic.hwid_hash or not secrets.compare_digest(lic.hwid_hash, digest):
        return jsonify({"valid": False, "error": "Licencia no vinculada a este dispositivo."}), 403
    if not license_is_valid(lic):
        return jsonify({"valid": False, "code": "EXPIRED", "error": "La licencia expiró."}), 403

    lic.last_seen_at = utc_now()
    db.session.commit()
    return jsonify({
        "valid": True,
        "tier": lic.tier,
        "expiresAt": lic.expires_at.isoformat() if lic.expires_at else None,
    })

# -------------------------
# Administración
# -------------------------
@app.post("/api/admin/generar-licencia")
def generar_licencia():
    if not require_admin():
        return jsonify({"error": "Acceso denegado."}), 403
    if not rate_limit("admin-license", max_attempts=20, window_seconds=600):
        return jsonify({"error": "Demasiadas solicitudes admin."}), 429

    data = request.get_json(silent=True) or {}
    days = int(data.get("days", 0) or 0)
    tier = str(data.get("tier", "PRO")).upper().strip()
    count = min(max(int(data.get("count", 1) or 1), 1), 100)
    if tier not in {"PRO", "LIFETIME"}:
        return jsonify({"error": "Tier inválido."}), 400
    if days < 0 or days > 3650:
        return jsonify({"error": "days inválido."}), 400
    if tier == "LIFETIME":
        days = 0

    created = []
    for _ in range(count):
        code = "ZETA-PRO-" + "-".join(secrets.token_hex(3).upper() for _ in range(3))
        expires_at = utc_now() + timedelta(days=days) if days else None
        lic = License(codigo=code, tier=tier, expires_at=expires_at)
        db.session.add(lic)
        created.append({"codigo": code, "tier": tier, "vence": expires_at.isoformat() if expires_at else None})
    db.session.commit()
    return jsonify({"licencias": created}), 201


@app.post("/api/admin/ventas")
def admin_ventas():
    if not require_admin():
        return jsonify({"error": "Acceso denegado."}), 403
    data = request.get_json(silent=True) or {}
    email = clean_email(str(data.get("email", "")))
    amount = int(data.get("cantidad", 0) or 0)
    if not email or amount == 0:
        return jsonify({"error": "email y cantidad son obligatorios."}), 400
    user = db.session.get(User, email)
    if not user:
        return jsonify({"error": "Usuario no encontrado."}), 404
    user.ventas = max(0, user.ventas + amount)
    db.session.commit()
    return jsonify(user_payload(user))


@app.post("/api/admin/revocar-licencia")
def revocar_licencia():
    if not require_admin():
        return jsonify({"error": "Acceso denegado."}), 403
    data = request.get_json(silent=True) or {}
    codigo = str(data.get("licencia", "")).strip().upper()
    lic = License.query.filter_by(codigo=codigo).first()
    if not lic:
        return jsonify({"error": "Licencia no encontrada."}), 404
    lic.status = "revoked"
    if lic.user_email:
        user = db.session.get(User, lic.user_email)
        if user:
            user.licencia_activada = False
    db.session.commit()
    return jsonify({"mensaje": "Licencia revocada."})


@app.post("/api/client/validate")
def client_validate():
    """Validación para el launcher/cliente Pro.

    No depende de la sesión del navegador: la licencia se prueba contra el HWID
    que el cliente obtiene en Windows. El servidor nunca recibe el HWID en claro
    en la base; guarda únicamente SHA-256.
    """
    if not rate_limit("client-validate", max_attempts=30, window_seconds=300):
        return jsonify({"valid": False, "error": "Demasiadas validaciones. Probá más tarde."}), 429

    data = request.get_json(silent=True) or {}
    codigo = str(data.get("licencia", "")).strip().upper()
    hwid = str(data.get("hwid", "")).strip()
    if not codigo or not hwid:
        return jsonify({"valid": False, "error": "Licencia y HWID son obligatorios."}), 400

    lic = License.query.filter_by(codigo=codigo).first()
    if not lic or lic.status != "bound" or not lic.hwid_hash:
        return jsonify({"valid": False, "error": "Licencia no válida o no activada."}), 403

    digest = hash_hwid(hwid)
    if not secrets.compare_digest(lic.hwid_hash, digest):
        return jsonify({"valid": False, "code": "HWID_MISMATCH", "error": "Este dispositivo no está autorizado."}), 403
    if not license_is_valid(lic):
        return jsonify({"valid": False, "code": "EXPIRED", "error": "La licencia expiró."}), 403

    lic.last_seen_at = utc_now()
    db.session.commit()
    return jsonify({
        "valid": True,
        "tier": lic.tier,
        "expiresAt": lic.expires_at.isoformat() if lic.expires_at else None,
    })


@app.post("/api/admin/reset-hwid")
def admin_reset_hwid():
    if not require_admin():
        return jsonify({"error": "Acceso denegado."}), 403
    data = request.get_json(silent=True) or {}
    email = clean_email(str(data.get("email", "")))
    codigo = str(data.get("licencia", "")).strip().upper()
    lic = License.query.filter_by(codigo=codigo).first() if codigo else None
    user = db.session.get(User, email) if email else None
    if not user and not lic:
        return jsonify({"error": "Indicá email o licencia."}), 400
    if lic:
        lic.hwid_hash = None
        lic.status = "spare"
        lic.user_email = None
        lic.bound_at = None
        lic.last_seen_at = None
    if user:
        user.hwid_hash = None
        user.licencia_activada = False
        bound = License.query.filter_by(user_email=user.email, status="bound").all()
        for other in bound:
            other.status = "spare"
            other.user_email = None
            other.hwid_hash = None
            other.bound_at = None
            other.last_seen_at = None
    db.session.commit()
    return jsonify({"mensaje": "HWID restablecido."})


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Solicitud demasiado grande."}), 413


@app.errorhandler(500)
def internal_error(_):
    db.session.rollback()
    return jsonify({"error": "Error interno del servidor."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
