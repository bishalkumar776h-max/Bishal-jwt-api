#!/usr/bin/env python3
"""
JWT Generator API for Vercel
Supports: guest login, access token
"""
import os
import time
import json
import base64
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import my_pb2
import output_pb2

app = Flask(__name__)

# ==================== CONSTANTS ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ppmainecoonghj.com/MajorLogin"
INSPECT_URL = "https://100067.connect.garena.com/oauth/token/inspect"
EAT_CONVERT_URL = "https://api-otrss.garena.com/support/callback/"

# ==================== JWT HELPERS ====================
def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data, AES.block_size))

def decrypt_data(data):
    if len(data) % 16 != 0:
        return data
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return unpad(cipher.decrypt(data), AES.block_size)
    except:
        return data

def oauth_login(uid, password):
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    resp = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=10, verify=False)
    if resp.status_code != 200:
        raise Exception(f"OAuth failed: {resp.status_code}")
    data = resp.json()
    return data.get('access_token'), data.get('open_id')

def inspect_token(access_token):
    url = f"{INSPECT_URL}?token={access_token}"
    headers = {'User-Agent': "GarenaMSDK/4.0.19P9"}
    resp = requests.get(url, headers=headers, timeout=10, verify=False)
    if resp.status_code != 200:
        raise Exception(f"Inspect failed: {resp.status_code}")
    data = resp.json()
    return data.get('open_id')

def major_login(access_token, open_id):
    # Try platforms 1 to 9
    for platform in range(1, 10):
        try:
            game = my_pb2.GameData()
            game.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            game.game_name = "free fire"
            game.game_version = 1
            game.version_code = "1.111.1"
            game.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
            game.device_type = "Handheld"
            game.network_provider = "Verizon Wireless"
            game.connection_type = "WIFI"
            game.screen_width = 1280
            game.screen_height = 960
            game.dpi = "240"
            game.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            game.total_ram = 5951
            game.gpu_name = "Adreno (TM) 640"
            game.gpu_version = "OpenGL ES 3.0"
            game.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            game.ip_address = "172.190.111.97"
            game.language = "en"
            game.open_id = open_id
            game.access_token = access_token
            game.platform_type = platform
            game.field_99 = str(platform)
            game.field_100 = str(platform)

            ser = game.SerializeToString()
            enc = encrypt_data(ser)
            headers = {
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
                "Content-Type": "application/octet-stream",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB55"
            }
            resp = requests.post(MAJOR_LOGIN_URL, data=enc, headers=headers, verify=False, timeout=10)
            if resp.status_code == 200:
                dec = decrypt_data(resp.content)
                msg = output_pb2.Garena_420()
                msg.ParseFromString(dec)
                if msg.token:
                    return msg.token
                else:
                    # fallback text search
                    text = dec.decode('utf-8', errors='ignore')
                    start = text.find("eyJ")
                    if start != -1:
                        end = start
                        while end < len(text) and text[end] not in ['"', ' ', '\n', '\r', '\t', '\x00']:
                            end += 1
                        jwt = text[start:end]
                        if jwt.count('.') >= 2:
                            return jwt
        except Exception:
            
            pass

      
        time.sleep(0.1)

    # If all platforms fail
    raise Exception("No JWT found after trying all platforms 1-9")

# ==================== EAT TOKEN CONVERSION ====================
def extract_eat_token(raw_input):
    
    if not raw_input:
        return None
    raw = str(raw_input).strip()
    
    if raw.startswith(('http://', 'https://')):
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(raw)
            qs = parse_qs(parsed.query)
            if 'eat' in qs:
                return qs['eat'][0]
        except:
            pass
     
        import re
        match = re.search(r'[a-fA-F0-9]{64,}', raw)
        if match:
            return match.group(0)
    
    import re
    if re.fullmatch(r'[a-fA-F0-9]{64,}', raw):
        return raw
   
    match = re.search(r'[a-fA-F0-9]{64,}', raw)
    if match:
        return match.group(0)
    return None

def eat_token_to_access_token(eat_token):
    
    url = f"{EAT_CONVERT_URL}?access_token={eat_token}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    }
    session = requests.Session()
    # Disable auto redirect, we'll follow manually
    resp = session.get(url, headers=headers, allow_redirects=False, verify=False)
    redirect_count = 0
    max_redirects = 10
    while 300 <= resp.status_code < 400 and redirect_count < max_redirects:
        location = resp.headers.get('location')
        if not location:
            break
        
        next_url = location if location.startswith('http') else requests.compat.urljoin(url, location)
        resp = session.get(next_url, headers=headers, allow_redirects=False, verify=False)
        redirect_count += 1
    final_url = resp.url

    
    parsed = urlparse(final_url)
    qs = parse_qs(parsed.query)
    access_token = qs.get('access_token', [None])[0]
    if access_token:
        return access_token, final_url

   
    if resp.text:
        try:
            data = json.loads(resp.text)
            access_token = data.get('access_token') or data.get('token')
            if access_token:
                return access_token, final_url
        except:
            pass
        
        import re
        match = re.search(r'[a-fA-F0-9]{64,}', resp.text)
        if match:
            return match.group(0), final_url
    raise Exception("Access token not found in final URL or response")

# ==================== FLASK ROUTES =================
@app.route('/jwt', methods=['GET', 'POST'])
def generate_jwt():
    # Parse parameters
    if request.method == 'GET':
        args = request.args
        uid = args.get('uid')
        password = args.get('password')
        access_token = args.get('access_token')
        open_id = args.get('open_id')
        eat_token = args.get('eat_token')
    else:  # POST
        data = request.get_json() or {}
        uid = data.get('uid')
        password = data.get('password')
        access_token = data.get('access_token')
        open_id = data.get('open_id')
        eat_token = data.get('eat_token')

    try:
        
        if eat_token:
           
            token = extract_eat_token(eat_token)
            if not token:
                return jsonify({'error': 'Invalid eat_token format'}), 400

            access_token, _ = eat_token_to_access_token(token)
           
        
        if uid and password:
            at, oid = oauth_login(uid, password)
            jwt = major_login(at, oid)
            return jsonify({'jwt': jwt})

        elif access_token:
            if not open_id:
                open_id = inspect_token(access_token)
            jwt = major_login(access_token, open_id)
            return jsonify({'jwt': jwt})
        else:
            return jsonify({'error': 'Provide (uid+password) or access_token or eat_token'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})
    
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'JWT Generator API is running', 'endpoints': {'/token': 'GET/POST with uid/password or access_token'}})


