import os
import requests
import logging
from flask import Flask, render_template, request
from urllib.parse import urlparse, unquote
import re

app = Flask(__name__,
            template_folder='app/templates',
            static_folder='app/static')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define allowed base paths (intentionally vulnerable)
ALLOWED_PATHS = [
    '/var/www/html/',
    '/home/user/',
    '/tmp/'
]

def is_safe_path(path):
    """Vulnerable check: only checks if any allowed path is a substring"""
    # Remove any leading/trailing slashes for comparison
    path = path.strip('/')
    return any(allowed.strip('/') in path for allowed in ALLOWED_PATHS)

def sanitize_url(url):
    """Sanitize and validate URL input"""
    try:
        parsed = urlparse(url)
        return parsed.scheme, parsed.netloc, parsed.path
    except Exception as e:
        logger.error(f"URL parsing error: {str(e)}")
        return None, None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    target = request.form.get('url', '')
    if not target:
        return render_template('result.html', content="No URL provided")

    try:
        scheme, netloc, path = sanitize_url(target)

        if not scheme:
            return render_template('result.html', content="Invalid URL format")

        # Handle HTTP/HTTPS requests
        if scheme in ['http', 'https']:
            if not netloc:
                return render_template('result.html', content="Invalid domain")

            # Basic domain validation
            if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', netloc):
                response = requests.get(target, timeout=3)
                content = response.text
            else:
                content = "Invalid domain format"

        elif scheme == 'file':
            # Decode URL-encoded paths
            decoded_path = unquote(path)
            
            # Remove leading slash if present
            if decoded_path.startswith('/'):
                decoded_path = decoded_path[1:]
            
            # Vulnerable path check (substring match)
            if not is_safe_path(decoded_path):
                content = "Access denied: Path not in allowed directories"
            else:
                try:
                    # Use the original path for file reading
                    with open(decoded_path, 'r') as f:
                        content = f.read()
                except Exception as e:
                    content = f"Error reading file: {str(e)}"

        else:
            content = "Unsupported URL scheme"

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        content = f"Error fetching URL: {str(e)}"
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        content = f"An unexpected error occurred: {str(e)}"

    return render_template('result.html', content=content)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)