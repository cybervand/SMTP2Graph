import os
import secrets
from copy import deepcopy
from hmac import compare_digest
from functools import wraps
from pathlib import Path

import docker
import yaml
from flask import Flask, flash, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/config.yml"))
SMTP2GRAPH_CONTAINER = os.environ.get("SMTP2GRAPH_CONTAINER", "smtp2graph")
UI_USERNAME = os.environ.get("UI_USERNAME", "admin")
UI_PORT = int(os.environ.get("UI_PORT", "16666"))
SECRET_KEY_PATH = Path(
    os.environ.get(
        "UI_SECRET_KEY_FILE",
        str(CONFIG_PATH.parent / ".smtp2graph-admin-secret"),
    )
)
PASSWORD_HASH_PATH = Path(
    os.environ.get(
        "UI_PASSWORD_HASH_FILE",
        os.environ.get(
            "UI_PASSWORD_HASH_PATH",
            str(CONFIG_PATH.parent / "admin-password.hash"),
        ),
    )
)


def env_or_file(name: str, *file_names: str) -> str | None:
    value = os.environ.get(name)
    if value:
        return value

    for file_name in file_names:
        file_path = os.environ.get(file_name)
        if file_path:
            path = Path(file_path)
            if not path.exists():
                continue
            return path.read_text(encoding="utf-8").strip()

    return None


def load_secret_key() -> str:
    env_secret = env_or_file("UI_SECRET_KEY", "UI_SECRET_KEY_FILE", "UI_SECRET_KEY_PATH")
    if env_secret:
        return env_secret

    if SECRET_KEY_PATH.exists():
        return SECRET_KEY_PATH.read_text(encoding="utf-8").strip()

    SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(48)
    SECRET_KEY_PATH.write_text(secret, encoding="utf-8")
    return secret


def load_password_hash() -> tuple[str | None, str]:
    password_hash = env_or_file(
        "UI_PASSWORD_HASH",
        "UI_PASSWORD_HASH_FILE",
        "UI_PASSWORD_HASH_PATH",
    )
    if password_hash:
        return password_hash, "hash"

    plaintext_password = env_or_file("UI_PASSWORD", "UI_PASSWORD_FILE", "UI_PASSWORD_PATH")
    if plaintext_password:
        return generate_password_hash(plaintext_password), "plaintext-env"

    return None, "setup-required"


app.secret_key = load_secret_key()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("UI_SECURE_COOKIES", "").lower() in {"1", "true", "yes", "on"}
)


def current_auth_state() -> tuple[str | None, str]:
    return load_password_hash()


def check_auth(username: str, password: str) -> bool:
    password_hash, _ = current_auth_state()
    if not password_hash:
        return False
    return compare_digest(username, UI_USERNAME) and check_password_hash(
        password_hash, password
    )


def is_authenticated() -> bool:
    return session.get("authenticated") is True


def password_setup_required() -> bool:
    password_hash, _ = current_auth_state()
    return password_hash is None


def safe_next_url(next_url: str | None) -> str:
    if not next_url or not next_url.startswith("/"):
        return url_for("index")
    if next_url.startswith("//"):
        return url_for("index")
    return next_url


def requires_auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if password_setup_required():
            return redirect(url_for("setup_admin"))
        if not is_authenticated():
            return redirect(url_for("login", next=request.path))
        return func(*args, **kwargs)

    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    if password_setup_required():
        return redirect(url_for("setup_admin"))

    if is_authenticated():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if check_auth(username, password):
            session.clear()
            session["authenticated"] = True
            session["username"] = UI_USERNAME
            return redirect(safe_next_url(request.form.get("next")))

        flash("Invalid username or password.", "error")

    _, auth_mode = current_auth_state()
    return render_template(
        "login.html",
        next_url=safe_next_url(
            request.args.get("next", request.form.get("next", url_for("index")))
        ),
        username=UI_USERNAME,
        auth_mode=auth_mode,
    )


def save_admin_password(password: str) -> None:
    PASSWORD_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    password_hash = generate_password_hash(password)
    PASSWORD_HASH_PATH.write_text(password_hash, encoding="utf-8")


@app.route("/setup", methods=["GET", "POST"])
def setup_admin():
    if not password_setup_required():
        if is_authenticated():
            return redirect(url_for("index"))
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password:
            flash("Password may not be empty.", "error")
        elif password != confirm_password:
            flash("Passwords did not match.", "error")
        else:
            save_admin_password(password)
            session.clear()
            session["authenticated"] = True
            session["username"] = UI_USERNAME
            flash("Admin password created.", "success")
            return redirect(url_for("index"))

    return render_template(
        "setup.html",
        username=UI_USERNAME,
        password_hash_path=str(PASSWORD_HASH_PATH),
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/download/tls-cert")
@requires_auth
def download_tls_cert():
    cert_file = configured_tls_cert_file()
    if not cert_file:
        flash("Configured TLS certificate file was not found.", "error")
        return redirect(url_for("index"))

    download_name = cert_file.stem
    if not download_name.lower().endswith(".crt"):
        download_name = f"{download_name}.crt"

    return send_file(
        cert_file,
        as_attachment=True,
        download_name=download_name,
        mimetype="application/x-x509-ca-cert",
    )


def default_config():
    return {
        "mode": "full",
        "send": {
            "appReg": {
                "tenant": "",
                "id": "",
                "secret": "",
            },
            "forceMailbox": "smtp@sens.no",
        },
        "receive": {
            "port": 587,
            "secure": False,
            "requireAuth": False,
            "ipWhitelist": ["192.168.180.0/24"],
            "allowedFrom": ["smtp@sens.no"],
        },
    }


def load_config():
    if not CONFIG_PATH.exists():
        return default_config()

    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    merged = default_config()
    merged.update(data)
    merged.setdefault("send", {}).setdefault("appReg", {})
    merged.setdefault("receive", {})
    return merged


def save_config(data):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)


def split_lines(value: str):
    return [line.strip() for line in value.splitlines() if line.strip()]


def parse_optional_int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    return int(value)


def is_checked(form, name: str) -> bool:
    return form.get(name) == "on"


def configured_tls_cert_file(config: dict | None = None) -> Path | None:
    config = config or load_config()
    cert_path = config.get("receive", {}).get("tlsCertPath", "").strip()
    if not cert_path:
        return None

    cert_file = Path(cert_path)
    if cert_file.exists() and cert_file.is_file():
        return cert_file

    resolved = (CONFIG_PATH.parent / cert_path).resolve()
    if resolved.exists() and resolved.is_file():
        return resolved

    return None


def parse_smtp_users(form) -> list[dict]:
    users: list[dict] = []
    usernames = form.getlist("smtp_username")
    passwords = form.getlist("smtp_password")
    allowed_from_values = form.getlist("smtp_user_allowed_from")

    row_count = max(len(usernames), len(passwords), len(allowed_from_values))
    for index in range(row_count):
        username = (usernames[index] if index < len(usernames) else "").strip()
        password = passwords[index] if index < len(passwords) else ""
        allowed_from_raw = (
            allowed_from_values[index] if index < len(allowed_from_values) else ""
        )

        if not username and not password and not allowed_from_raw.strip():
            continue

        if not username or not password:
            continue

        user = {
            "username": username,
            "password": password,
        }
        allowed_from = split_lines(allowed_from_raw)
        if allowed_from:
            user["allowedFrom"] = allowed_from

        users.append(user)

    return users


def config_with_ui_defaults(config: dict) -> dict:
    config.setdefault("receive", {})
    users = config["receive"].get("users")
    if not users:
        config["receive"]["users"] = [{"username": "", "password": "", "allowedFrom": []}]
    return config


def restart_container():
    try:
        client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        container = client.containers.get(SMTP2GRAPH_CONTAINER)
        container.restart(timeout=10)
        return True, f"Container '{SMTP2GRAPH_CONTAINER}' restarted."
    except Exception as e:
        return False, str(e)


@app.route("/", methods=["GET", "POST"])
@requires_auth
def index():
    current_config = load_config()
    config = config_with_ui_defaults(deepcopy(current_config))
    tls_cert_download_available = configured_tls_cert_file(config) is not None

    if request.method == "POST":
        smtp_users = parse_smtp_users(request.form)
        new_config = deepcopy(current_config)
        new_config["mode"] = request.form.get("mode", "full").strip() or "full"

        send = new_config.setdefault("send", {})
        app_reg = send.setdefault("appReg", {})
        app_reg["tenant"] = request.form.get("tenant", "").strip()
        app_reg["id"] = request.form.get("client_id", "").strip()
        if is_checked(request.form, "use_client_secret"):
            app_reg["secret"] = request.form.get("client_secret", "").strip()
        else:
            app_reg.pop("secret", None)
        certificate_thumbprint = request.form.get("certificate_thumbprint", "").strip()
        certificate_private_key_path = request.form.get("certificate_private_key_path", "").strip()
        if is_checked(request.form, "use_certificate_auth"):
            certificate = app_reg.setdefault("certificate", {})
            certificate["thumbprint"] = certificate_thumbprint
            certificate["privateKeyPath"] = certificate_private_key_path
            if not certificate:
                app_reg.pop("certificate", None)
        else:
            app_reg.pop("certificate", None)

        if is_checked(request.form, "use_force_mailbox"):
            send["forceMailbox"] = request.form.get("force_mailbox", "").strip()
        else:
            send.pop("forceMailbox", None)

        if is_checked(request.form, "use_send_retry"):
            send_retry_limit = parse_optional_int(request.form.get("send_retry_limit", ""))
            send_retry_interval = parse_optional_int(request.form.get("send_retry_interval", ""))
            if send_retry_limit is not None:
                send["retryLimit"] = send_retry_limit
            else:
                send.pop("retryLimit", None)
            if send_retry_interval is not None:
                send["retryInterval"] = send_retry_interval
            else:
                send.pop("retryInterval", None)
        else:
            send.pop("retryLimit", None)
            send.pop("retryInterval", None)

        receive = new_config.setdefault("receive", {})
        receive["port"] = int(request.form.get("receive_port", "587"))
        receive["secure"] = request.form.get("secure") == "on"
        receive["requireAuth"] = request.form.get("require_auth") == "on"
        receive["allowInsecureAuth"] = request.form.get("allow_insecure_auth") == "on"

        receive_max_size = request.form.get("receive_max_size", "").strip()
        receive_banner = request.form.get("receive_banner", "").strip()
        if is_checked(request.form, "use_receive_max_size") and receive_max_size:
            receive["maxSize"] = receive_max_size
        else:
            receive.pop("maxSize", None)
        if is_checked(request.form, "use_receive_banner") and receive_banner:
            receive["banner"] = receive_banner
        else:
            receive.pop("banner", None)

        if smtp_users:
            receive["users"] = smtp_users
        else:
            receive.pop("users", None)

        tls_cert_path = request.form.get("tls_cert_path", "").strip()
        tls_key_path = request.form.get("tls_key_path", "").strip()
        listen_address = request.form.get("listen_address", "").strip()

        if is_checked(request.form, "use_tls") and tls_cert_path:
            receive["tlsCertPath"] = tls_cert_path
        else:
            receive.pop("tlsCertPath", None)
        if is_checked(request.form, "use_tls") and tls_key_path:
            receive["tlsKeyPath"] = tls_key_path
        else:
            receive.pop("tlsKeyPath", None)
        if is_checked(request.form, "use_listen_address") and listen_address:
            receive["listenAddress"] = listen_address
        else:
            receive.pop("listenAddress", None)
        if not is_checked(request.form, "use_tls"):
            receive["secure"] = False
            receive["allowInsecureAuth"] = False

        if is_checked(request.form, "use_ip_whitelist"):
            receive["ipWhitelist"] = split_lines(request.form.get("ip_whitelist", ""))
        else:
            receive.pop("ipWhitelist", None)

        if is_checked(request.form, "use_allowed_from"):
            receive["allowedFrom"] = split_lines(request.form.get("allowed_from", ""))
        else:
            receive.pop("allowedFrom", None)

        rate_limit_duration = parse_optional_int(request.form.get("rate_limit_duration", ""))
        rate_limit_limit = parse_optional_int(request.form.get("rate_limit_limit", ""))
        if is_checked(request.form, "use_rate_limit") and (rate_limit_duration is not None or rate_limit_limit is not None):
            rate_limit = receive.setdefault("rateLimit", {})
            if rate_limit_duration is not None:
                rate_limit["duration"] = rate_limit_duration
            else:
                rate_limit.pop("duration", None)
            if rate_limit_limit is not None:
                rate_limit["limit"] = rate_limit_limit
            else:
                rate_limit.pop("limit", None)
            if not rate_limit:
                receive.pop("rateLimit", None)
        else:
            receive.pop("rateLimit", None)

        auth_limit_duration = parse_optional_int(request.form.get("auth_limit_duration", ""))
        auth_limit_limit = parse_optional_int(request.form.get("auth_limit_limit", ""))
        if is_checked(request.form, "use_auth_limit") and (auth_limit_duration is not None or auth_limit_limit is not None):
            auth_limit = receive.setdefault("authLimit", {})
            if auth_limit_duration is not None:
                auth_limit["duration"] = auth_limit_duration
            else:
                auth_limit.pop("duration", None)
            if auth_limit_limit is not None:
                auth_limit["limit"] = auth_limit_limit
            else:
                auth_limit.pop("limit", None)
            if not auth_limit:
                receive.pop("authLimit", None)
        else:
            receive.pop("authLimit", None)

        new_config.pop("log", None)

        proxy_host = request.form.get("proxy_host", "").strip()
        proxy_port_raw = request.form.get("proxy_port", "").strip()
        proxy_protocol = request.form.get("proxy_protocol", "").strip() or "http"
        proxy_username = request.form.get("proxy_username", "").strip()
        proxy_password = request.form.get("proxy_password", "")

        if is_checked(request.form, "use_http_proxy") and proxy_host and proxy_port_raw:
            proxy_config = new_config.setdefault("httpProxy", {})
            proxy_config["host"] = proxy_host
            proxy_config["port"] = int(proxy_port_raw)
            proxy_config["protocol"] = proxy_protocol
            if is_checked(request.form, "use_proxy_auth") and proxy_username:
                proxy_config["username"] = proxy_username
            else:
                proxy_config.pop("username", None)
            if is_checked(request.form, "use_proxy_auth") and proxy_password:
                proxy_config["password"] = proxy_password
            else:
                proxy_config.pop("password", None)
        else:
            new_config.pop("httpProxy", None)

        save_config(new_config)
        if request.form.get("require_auth") == "on" and not smtp_users:
            flash("SMTP auth is enabled, but no SMTP users were saved.", "error")
        elif smtp_users:
            flash(f"Saved {len(smtp_users)} SMTP user(s).", "success")
        flash("Config saved.", "success")

        if request.form.get("action") == "save_restart":
            ok, output = restart_container()
            if ok:
                flash(output, "success")
            else:
                flash(f"Restart failed: {output}", "error")

        return redirect(url_for("index"))

    _, auth_mode = current_auth_state()
    return render_template(
        "index.html",
        config=config,
        ui_port=UI_PORT,
        config_path=str(CONFIG_PATH),
        username=session.get("username", UI_USERNAME),
        auth_mode=auth_mode,
        tls_cert_download_available=tls_cert_download_available,
    )


@app.route("/health", methods=["GET"])
def health():
    return {"ok": True, "config_path": str(CONFIG_PATH), "ui_port": UI_PORT}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=UI_PORT, debug=False)
