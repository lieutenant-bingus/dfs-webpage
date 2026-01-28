from flask import Flask, request, jsonify
from flask import send_from_directory
import os
import base64
import time
import re
import mimetypes
from datetime import datetime
import json
import requests
from requests.auth import HTTPBasicAuth
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

# Try to import psycopg2, but don't crash if not installed
try:
    import psycopg2
    import psycopg2.extras
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    print("WARNING: psycopg2 not installed. Database features disabled.")
    print("Install with: pip install psycopg2-binary")

app = Flask(__name__)

# In-memory storage for the most-recently received JSON
last_data = None

# Database configuration
DB_CONFIG = {
    "host": "10.1.10.173",
    "port": 5432,
    "database": "traffic_monitor",
    "user": "traffic_app",
    "password": "360Network"
}


def save_to_db(data):
    """Save webhook data to PostgreSQL database."""
    if not DB_AVAILABLE:
        return False
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        inner = data.get('data', {})
        
        # Parse timestamps (FLOW sends milliseconds as strings)
        start_ts = data.get('data_start_timestamp')
        end_ts = data.get('data_end_timestamp')
        
        data_start = None
        data_end = None
        if start_ts:
            try:
                data_start = datetime.fromtimestamp(int(start_ts) / 1000)
            except:
                pass
        if end_ts:
            try:
                data_end = datetime.fromtimestamp(int(end_ts) / 1000)
            except:
                pass
        
        # Calculate total vehicles from movement stats
        total = 0
        for stats in inner.get('movement_category_stats', []):
            if isinstance(stats, list):
                for cat in stats:
                    if isinstance(cat, dict):
                        total += cat.get('number', 0)
        
        # Insert into database
        cur.execute("""
            INSERT INTO traffic_snapshots 
            (data_start, data_end, granularity_ms, analytic_id, block_name, total_vehicles, raw_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            data_start,
            data_end,
            inner.get('granularity'),
            data.get('analytic_id'),
            data.get('block_name'),
            total,
            json.dumps(data)
        ))
        
        snapshot_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"✓ Saved to DB: snapshot #{snapshot_id}, {total} vehicles")
        return True
        
    except Exception as e:
        print(f"✗ Database error: {e}")
        return False


@app.route('/webhook', methods=['POST'])
@app.route('/webhook/', methods=['POST'])
def handle_webhook():
    if request.method == 'POST':
        # Debug: Log raw request info
        print("Content-Type:", request.content_type)
        print("Raw data length:", len(request.data))
        print("Raw data (first 2000 chars):", request.data[:2000])

        data = request.json  # Grab the incoming JSON
        print("Received JSON:", data)  # Log it to console for now
        # store latest payload in memory so the frontend can fetch it
        global last_data
        last_data = data or {}
        
        # Save to database (if available)
        save_to_db(data)

        # attempt to find base64 image data in common fields and save as a file
        frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
        images_dir = os.path.join(frontend_dir, 'static', 'images')
        try:
            os.makedirs(images_dir, exist_ok=True)
        except Exception:
            pass

        # recursive detector to find a data URI or large base64 anywhere in the JSON
        DATA_URI_RE = re.compile(r'^data:(image/[^;]+);base64,(.+)$', re.I)
        BASE64_LIKELY_RE = re.compile(r'^[A-Za-z0-9+/=\n\r]+$')

        def find_base64(obj, path=''):
            # returns tuple (b64_string, mime_or_None, json_path) or None
            if isinstance(obj, str):
                s = obj.strip()
                m = DATA_URI_RE.match(s)
                if m:
                    return m.group(2), m.group(1), path or '<root>'
                # heuristic: long base64-like strings
                if len(s) > 200 and BASE64_LIKELY_RE.match(s):
                    return s, None, path or '<root>'
                # short signature checks
                if s.startswith('iVBOR') or s.startswith('/9j/'):
                    return s, None, path or '<root>'
                return None
            if isinstance(obj, dict):
                for k, v in obj.items():
                    found = find_base64(v, f"{path}.{k}" if path else k)
                    if found:
                        return found
                return None
            if isinstance(obj, list):
                for i, item in enumerate(obj):
                    found = find_base64(item, f"{path}[{i}]")
                    if found:
                        return found
                return None
            return None

        found = find_base64(last_data)
        if found:
            img_b64, detected_mime, found_path = found
            print(f"Detected base64 image at {found_path} mime={detected_mime}")
            try:
                img_bytes = base64.b64decode(img_b64)
                # determine extension from MIME first, else probe bytes
                ext = None
                if detected_mime:
                    ext = mimetypes.guess_extension(detected_mime)
                    if ext == '.jpe':
                        ext = '.jpg'
                if not ext:
                    # probe common image signatures
                    def probe_image_type(bts):
                        if bts.startswith(b"\x89PNG\r\n\x1a\n"):
                            return 'png'
                        if bts.startswith(b"\xff\xd8\xff"):
                            return 'jpeg'
                        if bts[:6] in (b'GIF87a', b'GIF89a'):
                            return 'gif'
                        if bts.startswith(b'RIFF') and b'WEBP' in bts[8:12]:
                            return 'webp'
                        return None

                    kind = probe_image_type(img_bytes)
                    if kind:
                        ext = '.jpg' if kind == 'jpeg' else f'.{kind}'
                if not ext:
                    ext = '.png'

                filename = f"{int(time.time()*1000)}{ext}"
                save_path = os.path.join(images_dir, filename)
                with open(save_path, 'wb') as f:
                    f.write(img_bytes)
                last_data['image_url'] = f"/images/{filename}"
                last_data['_image_field'] = found_path
                print("Saved detected image to:", save_path)
            except Exception as e:
                print("Failed to decode/save detected image:", e)
        else:
            print('No base64/data-uri image found in payload')

        return jsonify({"status": "success", "message": "JSON received"}), 200
    return jsonify({"status": "error", "message": "Invalid method"}), 405


@app.route('/latest', methods=['GET'])
def get_latest():
    """Return the most recently received JSON payload (or empty object)."""
    if last_data is None:
        return jsonify({}), 200
    return jsonify(last_data), 200


@app.route('/images/<path:filename>')
def serve_image(filename):
    """Serve saved images from frontend/static/images."""
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    images_dir = os.path.join(frontend_dir, 'static', 'images')
    return send_from_directory(images_dir, filename)


@app.route('/current-image')
@app.route('/current-image/')
def serve_current_image():
    """
    Serve the most recent image directly.
    Point your FLOW widget to this URL: http://localhost:5000/current-image
    Returns the actual image file (not JSON), auto-refreshes with new webhooks.
    """
    from flask import redirect, abort, Response
    
    # If we have a saved image URL from the last webhook, redirect to it
    if last_data and last_data.get('image_url'):
        return redirect(last_data['image_url'])
    
    # Fallback: find the most recent image in the images folder
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    images_dir = os.path.join(frontend_dir, 'static', 'images')
    
    try:
        files = os.listdir(images_dir)
        image_files = [f for f in files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))]
        if image_files:
            # Sort by filename (timestamp) to get most recent
            image_files.sort(reverse=True)
            return redirect(f'/images/{image_files[0]}')
    except Exception:
        pass
    
    # No image available - return a placeholder
    abort(404, description="No image available yet. Send a webhook with image data first.")


@app.route('/', methods=['GET'])
def serve_frontend():
    """Serve the homepage from the sibling frontend folder."""
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    return send_from_directory(frontend_dir, 'index.html')


@app.route('/Ponce-de-Leon', methods=['GET'])
@app.route('/Ponce-de-Leon/', methods=['GET'])
@app.route('/ponce-de-leon', methods=['GET'])
@app.route('/ponce-de-leon/', methods=['GET'])
@app.route('/Ponce-and-Clifton', methods=['GET'])
@app.route('/Ponce-and-Clifton/', methods=['GET'])
@app.route('/ponce-and-clifton', methods=['GET'])
@app.route('/ponce-and-clifton/', methods=['GET'])
def serve_ponce_de_leon():
    """Serve the Ponce & Clifton traffic dashboard."""
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frontend')
    return send_from_directory(frontend_dir, 'ponce-de-leon.html')


@app.route('/images/logo.png')
def serve_logo():
    """Serve the logo from the root images folder."""
    root_dir = os.path.dirname(os.path.dirname(__file__))
    images_dir = os.path.join(root_dir, 'images')
    return send_from_directory(images_dir, 'logo.png')


# Camera Configuration
CAMERA_CONFIG = {
    'north': os.getenv('CAMERA_NORTH_IP', '192.168.1.1'),
    'south': os.getenv('CAMERA_SOUTH_IP', '192.168.1.2'),
    'east': os.getenv('CAMERA_EAST_IP', '192.168.1.3'),
    'west': os.getenv('CAMERA_WEST_IP', '192.168.1.4'),
}

CAMERA_USERNAME = os.getenv('CAMERA_USERNAME', 'root')
CAMERA_PASSWORD = os.getenv('CAMERA_PASSWORD', '360Network')


@app.route('/api/camera/<arm>', methods=['GET'])
def proxy_camera(arm):
    """
    Proxy MJPEG stream from Axis camera.
    Handles HTTP Basic Auth and streams the video feed to the frontend.
    """
    arm = arm.lower()
    
    if arm not in CAMERA_CONFIG:
        return jsonify({"error": "Invalid arm. Must be: north, south, east, or west"}), 400
    
    camera_ip = CAMERA_CONFIG[arm]
    
    # Construct Axis MJPEG URL
    camera_url = f'http://{camera_ip}/axis-cgi/mjpg/video.cgi'
    
    try:
        # Stream the MJPEG feed with Basic Auth
        response = requests.get(
            camera_url,
            auth=HTTPBasicAuth(CAMERA_USERNAME, CAMERA_PASSWORD),
            stream=True,
            timeout=10
        )
        
        if response.status_code != 200:
            return jsonify({
                "error": f"Camera returned status {response.status_code}",
                "camera": arm,
                "url": camera_url
            }), response.status_code
        
        # Return the MJPEG stream with appropriate headers
        def generate():
            try:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        yield chunk
            except Exception as e:
                print(f"Stream error for {arm}: {e}")
        
        return generate(), 200, {
            'Content-Type': response.headers.get('Content-Type', 'multipart/x-mixed-replace; boundary=myboundary'),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    
    except requests.exceptions.Timeout:
        return jsonify({"error": "Camera connection timeout", "camera": arm}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to camera", "camera": arm}), 503
    except Exception as e:
        print(f"Camera proxy error: {e}")
        return jsonify({"error": str(e), "camera": arm}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)