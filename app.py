import os
import requests
import logging
from flask import Flask, render_template, request
from urllib.parse import urlparse, unquote
import re
import tempfile

app = Flask(__name__,
            template_folder='app/templates',
            static_folder='app/static')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get base directory for CTF files
if os.name == 'posix':
    CTF_BASE = '/'
else:
    CTF_BASE = os.path.join(tempfile.gettempdir(), 'ctf_root')

ALLOWED_PATHS = [
    '/var/www/html/',
    '/home/user/',
    '/tmp/'
]

def get_ctf_path(unix_path):
    """Convert Unix-style path to actual filesystem path"""
    if os.name == 'posix':
        return unix_path
    else:
        # Convert Unix path to Windows path within CTF_BASE
        relative_path = unix_path.lstrip('/')
        return os.path.join(CTF_BASE, relative_path.replace('/', os.sep))

def setup_ctf_files():
    try:
        # Create directory structure
        dirs_to_create = [
            '/tmp/ctf',
            '/home/user/documents', 
            '/var/www/html/admin',
            '/home/user/.secret',
            '/etc'
        ]
        
        for unix_dir in dirs_to_create:
            actual_dir = get_ctf_path(unix_dir)
            os.makedirs(actual_dir, exist_ok=True)
        
        # File contents
        files_content = {
            '/tmp/ctf/readme.txt': """CTF Search Engine Challenge - Level 1

Welcome to the search engine CTF!
You've found the first file. Great job!

The admin keeps sensitive files in /home/user/documents/
Try to explore that directory to find more clues.

Files to look for:
- config.txt
- secrets.txt
""",
            '/home/user/documents/config.txt': """# Web Application Configuration

database_host=localhost
database_port=5432
admin_user=ctf_admin
admin_password=super_secret_123

All sensitive data has been moved to /var/www/html/admin/
Check the backup.txt file for more information

The final flag is hidden deeper in the system...
Look for hidden files starting with '.'
""",
            '/var/www/html/admin/backup.txt': """BACKUP LOG - CONFIDENTIAL

Recent backup operations:
- User data: /home/user/documents/ ✓
- System configs: /etc/passwd ✓
- Hidden files: /home/user/.secret/ ✓

The flag file has been moved to a hidden directory.
Path: /home/user/.secret/.flag.txt

Some files might be in /etc/ directory for system configuration.
Be careful with file:// protocol usage!

Administrator: Remember to check /etc/hosts for network configuration.
""",
            '/home/user/.secret/.flag.txt': """🎉 CONGRATULATIONS! 🎉

You have successfully exploited the URL parsing vulnerability!

FLAG: CTF{url_p4rs1ng_byp4ss_m4st3r_2024}

What you learned:
1. URL parsing confusion attacks
2. Authority section bypass techniques  
3. File:// protocol exploitation
4. Bypassing URL scheme validation

Vulnerability Details:
- URL parsing confusion between scheme and authority
- Insufficient validation of URL components
- Authority section can be used to bypass restrictions

Great job completing this CTF challenge!
""",
            '/etc/hosts': """127.0.0.1   localhost
::1         localhost
127.0.0.1   ctf-challenge.local
10.0.0.1    admin-panel.ctf
""",
            '/etc/passwd': """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ctf_user:x:1000:1000:CTF User:/home/user:/bin/bash
""",
            '/home/user/documents/secrets.txt': """SECRET KEYS AND TOKENS

API_KEY=sk-1234567890abcdef
DATABASE_PASSWORD=secretdb123
JWT_SECRET=mysupersecretjwtkey

IMPORTANT: Check the admin backup files for more sensitive information.
The real treasure is in the hidden .secret directory!
"""
        }
        
        # Create all files
        for unix_path, content in files_content.items():
            actual_path = get_ctf_path(unix_path)
            with open(actual_path, 'w') as f:
                f.write(content)
        
        logger.info("CTF files setup completed")
        
    except Exception as e:
        logger.error(f"Error setting up CTF files: {str(e)}")

def is_safe_path(path):
    # Remove leading/trailing slashes and normalize
    path = path.strip('/').replace('\\', '/')
    # Resolve any remaining path traversal
    path_parts = []
    for part in path.split('/'):
        if part == '..':
            if path_parts:
                path_parts.pop()
        elif part and part != '.':
            path_parts.append(part)
    
    resolved_path = '/'.join(path_parts)
    
    # Check if resolved path starts with or contains allowed paths
    for allowed in ALLOWED_PATHS:
        allowed_clean = allowed.strip('/')
        if resolved_path.startswith(allowed_clean) or allowed_clean in resolved_path:
            return True
    
    # Additional bypass keywords
    bypass_keywords = ['tmp', 'html', 'user', 'var', 'home']
    if any(keyword in resolved_path.lower() for keyword in bypass_keywords):
        return True
        
    return False

def sanitize_url(url):
    try:
        parsed = urlparse(url)
        return parsed.scheme, parsed.netloc, parsed.path
    except Exception as e:
        logger.error(f"URL parsing error: {str(e)}")
        return None, None, None

def validate_url_scheme(url):
    allowed_schemes = ['http', 'https']
    try:
        parsed = urlparse(url)
        return parsed.scheme.lower() in allowed_schemes
    except:
        return False

@app.route('/')
def index():
    setup_ctf_files()
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    target = request.form.get('url', '')
    if not target:
        return render_template('result.html', content="No URL provided")

    try:
        if not validate_url_scheme(target):
            return render_template('result.html', content="Only HTTP and HTTPS URLs are allowed")

        scheme, netloc, path = sanitize_url(target)

        if not scheme:
            return render_template('result.html', content="Invalid URL format")

        if scheme in ['http', 'https']:
            if not netloc:
                return render_template('result.html', content="Invalid domain")

            if re.match(r'^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$', netloc):
                try:
                    response = requests.get(target, timeout=3)
                    content = response.text[:5000]
                except:
                    content = "Error fetching external URL"
            else:
                if '@file://' in target:
                    file_part = target.split('@file://')[1]
                    
                    decoded_path = unquote(unquote(file_part))
                    
                    # Normalize path separators
                    decoded_path = decoded_path.replace('\\', '/')
                    
                    # For path validation, remove leading slash and resolve path traversal
                    check_path = decoded_path.lstrip('/')
                    # Resolve path traversal sequences
                    resolved_path = os.path.normpath(check_path).replace('\\', '/')
                    
                    logger.info(f"Original path: {file_part}")
                    logger.info(f"Decoded path: {decoded_path}")
                    logger.info(f"Check path: {check_path}")
                    logger.info(f"Resolved path: {resolved_path}")
                    logger.info(f"Path validation result: {is_safe_path(resolved_path)}")
                    
                    if not is_safe_path(resolved_path):
                        content = f"Access denied: Path '{decoded_path}' resolves to '{resolved_path}' which is not in allowed directories.\nAllowed: {', '.join(ALLOWED_PATHS)}"
                    else:
                        try:
                            # Get the actual file system path
                            target_path = get_ctf_path(decoded_path)
                            target_path = os.path.normpath(target_path)
                            
                            logger.info(f"Accessing: {target_path}")
                            
                            if os.path.isdir(target_path):
                                try:
                                    files = os.listdir(target_path)
                                    content = f"Directory listing for {decoded_path}:\n\n"
                                    for file in sorted(files):
                                        file_path = os.path.join(target_path, file)
                                        if os.path.isdir(file_path):
                                            content += f"[DIR]  {file}/\n"
                                        else:
                                            content += f"[FILE] {file}\n"
                                    
                                    if not files:
                                        content += "(empty directory)"
                                        
                                except PermissionError:
                                    content = f"Permission denied: Cannot list directory {decoded_path}"
                            
                            elif os.path.exists(target_path):
                                try:
                                    with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                                        file_content = f.read(10000)
                                        content = f"File: {decoded_path}\n{'='*50}\n{file_content}"
                                except PermissionError:
                                    content = f"Permission denied: Cannot read file {decoded_path}"
                                except Exception as e:
                                    content = f"Error reading file {decoded_path}: {str(e)}"
                            else:
                                content = f"File not found: {decoded_path}"

                        except Exception as e:
                            logger.error(f"File access error: {str(e)}")
                            content = f"Error accessing file: {str(e)}"
                else:
                    content = "Invalid domain format"

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