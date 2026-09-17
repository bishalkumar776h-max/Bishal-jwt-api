import os
import sys
import json
import base64
import binascii
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests

# ============== Protobuf Import with Fallback ==============
try:
    import my_pb2
    import output_pb2
except ImportError:
    # For environments where protobuf files might not exist
    my_pb2 = None
    output_pb2 = None

# ============== Logging Setup ==============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============== Configuration ==============
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
PORT = int(os.environ.get('PORT', 5000))  # Default 5000 for Render/Vercel

# ============== Helper Functions ==============
def decrypt_jwt(token):
    """Manually decode JWT without cryptography library"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        
        payload = parts[1]
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding
        
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception as e:
        logger.warning(f"JWT decode failed: {e}")
        return {}

def encrypt_message(plaintext):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        padded_message = pad(plaintext, AES.block_size)
        return cipher.encrypt(padded_message)
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def fetch_open_id(access_token):
    """Fetch OpenID from access token"""
    try:
        uid_url = "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/"
        uid_headers = {
            "accept": "application/json, text/plain, */*",
            "access-token": access_token,
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36"
        }

        uid_res = requests.get(uid_url, headers=uid_headers, timeout=15)
        uid_data = uid_res.json()
        uid = uid_data.get("uid")

        if not uid:
            return None, "Failed to extract UID"

        openid_url = "https://shop2game.com/api/auth/player_id_login"
        openid_headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36"
        }
        payload = {
            "app_id": 100067,
            "login_id": str(uid)
        }

        openid_res = requests.post(openid_url, headers=openid_headers, json=payload, timeout=15)
        openid_data = openid_res.json()
        open_id = openid_data.get("open_id")

        if not open_id:
            return None, "Failed to extract open_id"

        return open_id, None

    except Exception as e:
        logger.error(f"Fetch open_id error: {e}")
        return None, str(e)

def create_game_data(open_id, access_token, platform_type):
    """Create protobuf game data"""
    if my_pb2 is None:
        # Fallback if protobuf not available
        return None
    
    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.111.1"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = open_id
    game_data.access_token = access_token
    game_data.platform_type = platform_type
    game_data.field_99 = str(platform_type)
    game_data.field_100 = str(platform_type)
    return game_data

# ============== Routes ==============
@app.route('/', methods=['GET'])
def home():
    """Home endpoint for health check"""
    return jsonify({
        "status": "running",
        "service": "Free Fire Auth API",
        "version": "1.0",
        "endpoints": {
            "/access-jwt": "GET with access_token and optional open_id",
            "/token": "GET with uid and password",
            "/health": "GET for health check"
        }
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/access-jwt', methods=['GET'])
def majorlogin_jwt():
    try:
        access_token = request.args.get('access_token')
        provided_open_id = request.args.get('open_id')

        if not access_token:
            return jsonify({"error": "missing access_token"}), 400

        # Get open_id
        open_id = provided_open_id
        if not open_id:
            open_id, error = fetch_open_id(access_token)
            if error:
                return jsonify({"error": f"Failed to fetch open_id: {error}"}), 400

        if not open_id:
            return jsonify({"error": "Failed to get open_id"}), 400

        platforms = [8, 3, 4, 6]
        logger.info(f"MajorLogin attempt for open_id: {open_id}")

        for platform_type in platforms:
            try:
                # Create and encrypt game data
                game_data = create_game_data(open_id, access_token, platform_type)
                if game_data is None:
                    continue
                    
                serialized_data = game_data.SerializeToString()
                encrypted_data = encrypt_message(serialized_data)
                hex_encrypted_data = binascii.hexlify(encrypted_data).decode('utf-8')

                # Send request
                url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
                headers = {
                    "Accept": "*/*",
                    "Accept-Encoding": "deflate, gzip",
                    "Authorization": "Bearer",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "ReleaseVersion": "OB55",
                    "User-Agent": "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
                    "X-GA": "v1 1",
                    "X-Unity-Version": "2022.3.47f1"
                }
                
                edata = bytes.fromhex(hex_encrypted_data)
                response = requests.post(url, data=edata, headers=headers, verify=False, timeout=15)

                if response.status_code == 200:
                    data_dict = None
                    
                    # Try protobuf parsing
                    if output_pb2 is not None:
                        try:
                            example_msg = output_pb2.Garena_420()
                            example_msg.ParseFromString(response.content)
                            data_dict = {field.name: getattr(example_msg, field.name)
                                         for field in example_msg.DESCRIPTOR.fields
                                         if field.name not in ["binary", "binary_data", "Garena420"]}
                        except Exception:
                            pass
                    
                    # Fallback to JSON
                    if not data_dict:
                        try:
                            data_dict = response.json()
                        except ValueError:
                            continue

                    if data_dict and "token" in data_dict:
                        token_value = data_dict["token"]
                        decoded_token = decrypt_jwt(token_value)

                        result = {
                            "account_id": decoded_token.get("account_id"),
                            "account_name": decoded_token.get("nickname"),
                            "open_id": open_id,
                            "access_token": access_token,
                            "platform": decoded_token.get("external_type"),
                            "region": decoded_token.get("lock_region"),
                            "status": "success",
                            "token": token_value
                        }
                        logger.info(f"Success for platform: {platform_type}")
                        return jsonify(result), 200
                        
            except Exception as e:
                logger.warning(f"Platform {platform_type} error: {e}")
                continue

        return jsonify({"error": "No valid platform found"}), 400
        
    except Exception as e:
        logger.error(f"MajorLogin error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/token', methods=['GET'])
def oauth_guest():
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        
        if not uid or not password:
            return jsonify({"error": "Missing uid or password"}), 400

        oauth_url = "https://100067.connect.garena.com/oauth/guest/token/grant"
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
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded"
        }

        oauth_response = requests.post(oauth_url, data=payload, headers=headers, timeout=15, verify=False)
        
        if oauth_response.status_code != 200:
            try:
                return jsonify(oauth_response.json()), oauth_response.status_code
            except ValueError:
                return jsonify({"error": oauth_response.text}), oauth_response.status_code

        oauth_data = oauth_response.json()
        
        if 'access_token' not in oauth_data or 'open_id' not in oauth_data:
            return jsonify({"error": "OAuth response missing access_token or open_id"}), 500

        params = {
            'access_token': oauth_data['access_token'],
            'open_id': oauth_data['open_id']
        }
        
        with app.test_request_context('/api/token', query_string=params):
            return majorlogin_jwt()
            
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return jsonify({"error": str(e)}), 500

# ============== Vercel Handler ==============
def handler(request):
    """Vercel serverless handler"""
    return app(request)

# ============== Main ==============
if __name__ == '__main__':
    host = '0.0.0.0'
    logger.info(f"Starting server on {host}:{PORT}")
    logger.info(f"Local: http://localhost:{PORT}")
    app.run(host=host, port=PORT, debug=False, threaded=True)
