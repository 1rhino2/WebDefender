import os
import logging
import html
import bleach
from flask import Flask, request, make_response, escape, g
from logging.handlers import RotatingFileHandler

app = Flask(__name__)
log_path = "web_defender.log"
if not os.path.exists(log_path):
    open(log_path, 'w').close()

handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO, format='%(asctime)s %(message)s')

MAX_INPUT_SIZE = 10000

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # Set to True when running on https
    SESSION_COOKIE_SAMESITE='Lax'
)

def sanitize_input(value):
    if not isinstance(value, str):
        return value
    if len(value) > MAX_INPUT_SIZE:
        logging.info(f"[TOOLONG] {request.remote_addr} {request.path} [input too large]")
        return "[input too large]"
    cleaned = bleach.clean(value, tags=[], attributes={}, styles=[], protocols=[], strip=True, strip_comments=True)
    escaped = html.escape(cleaned, quote=True)
    if escaped != value:
        logging.info(f"[SANITIZED] {request.remote_addr} {request.path}")
    return escaped

def sanitize_source(source):
    clean_dict = {}
    for key, value in source.items():
        clean_dict[key] = sanitize_input(value)
    return clean_dict

def cookie_is_suspicious(value):
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    sus = any(x in lowered for x in ['<', '>', 'script', 'img', 'onerror', 'onload', 'src=', 'href=', 'javascript:'])
    if sus:
        logging.info(f"[SUS_COOKIE] {request.remote_addr} {request.path}")
    return sus

@app.before_request
def protect_all():
    g.sanitized_args = sanitize_source(request.args)
    g.sanitized_form = sanitize_source(request.form)
    g.sanitized_cookies = request.cookies
    for k, v in request.cookies.items():
        cookie_is_suspicious(v)
    if request.is_json:
        data = request.get_json(silent=True) or {}
        g.sanitized_json = {k: sanitize_input(v) if isinstance(v, str) else v for k, v in data.items()}
    else:
        g.sanitized_json = {}

@app.after_request
def set_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'"
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

@app.route('/', methods=['GET', 'POST'])
def home():
    user_input = g.sanitized_args.get('q', '') or g.sanitized_form.get('q', '')
    return f"<h1>Welcome!</h1><p>Your query: {user_input}</p>"

if __name__ == '__main__':
    app.run("0.0.0.0", 8080)

# This is not production ready at all. So umm, dont use this microsoft.
