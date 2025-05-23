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

if os.name == 'posix':
    CTF_BASE = '/'
else:
    CTF_BASE = os.path.join(tempfile.gettempdir(), 'ctf_root')

ALLOWED_PATHS = [
    '/var/www/html/',
    '/home/user/',
    '/tmp/',
    '/etc/'
]

def get_ctf_path(unix_path):
    """Convert Unix-style path to actual filesystem path"""
    unix_path = unix_path.replace('\\', '/')
    
    if not unix_path.startswith('/'):
        unix_path = '/' + unix_path
    
    path_parts = []
    for part in unix_path.strip('/').split('/'):
        if part == '..':
            if path_parts:
                path_parts.pop()
        elif part and part != '.':
            path_parts.append(part)
    
    resolved_unix_path = '/' + '/'.join(path_parts)
    
    if os.name == 'posix':
        return resolved_unix_path
    else:
        relative_path = resolved_unix_path.lstrip('/')
        return os.path.join(CTF_BASE, relative_path.replace('/', os.sep))

def setup_ctf_files():
    try:
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
            logger.info(f"Created directory: {actual_dir}")
        
        secret_dir = get_ctf_path('/home/user/.secret')
        if not os.path.exists(secret_dir):
            logger.error(f"Failed to create .secret directory: {secret_dir}")
            os.makedirs(secret_dir, exist_ok=True)
            logger.info(f"Manually created .secret directory: {secret_dir}")
        
        # File contents
        files_content = {
            '/tmp/ctf/readme.txt': """CTF Search Engine Challenge - Level 1

Welcome to the search engine CTF!
You've found the first file. Great job!


Try to explore that directory to find more clues.

Look for other files also :

""",
            '/home/user/documents/config.txt': """# Web Application Configuration

database_host=localhost
database_port=5432
admin_user=ctf_admin
admin_password=super_secret_123

All sensitive data has been moved to other files, so keep exploring.
""",
            '/var/www/html/admin/backup.txt': """BACKUP LOG - CONFIDENTIAL

Recent backup operations:
- User data: /home/user/documents/ ✓
- System configs: /etc/passwd ✓
- Hidden files: You have to explore it by yourself ✓


""",
            '/home/user/.secret/.flag.txt': """🎉 CONGRATULATIONS! 🎉

You have successfully exploited the URL parsing vulnerability!

FLAG: F23A{url_p4rs1ng_byp4ss_m4st3r_2025}

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

IMPORTANT: Oops this is secret file not the flag file
"""
        }
        
        for unix_path, content in files_content.items():
            actual_path = get_ctf_path(unix_path)
            parent_dir = os.path.dirname(actual_path)
            os.makedirs(parent_dir, exist_ok=True)
            
            logger.info(f"Creating file: {unix_path} -> {actual_path}")
            
            try:
                with open(actual_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Successfully created: {actual_path}")
            except Exception as file_error:
                logger.error(f"Failed to create file {actual_path}: {file_error}")
        
        flag_path = get_ctf_path('/home/user/.secret/.flag.txt')
        if not os.path.exists(flag_path):
            logger.error(f"Flag file not found at: {flag_path}")
            try:
                with open(flag_path, 'w', encoding='utf-8') as f:
                    f.write(files_content['/home/user/.secret/.flag.txt'])
                logger.info(f"Manually created flag file: {flag_path}")
            except Exception as e:
                logger.error(f"Failed to manually create flag file: {e}")
        else:
            logger.info(f"Flag file exists: {flag_path}")
        
        logger.info("CTF files setup completed")
        
    except Exception as e:
        logger.error(f"Error setting up CTF files: {str(e)}")

def is_safe_path(path):
    path = path.strip('/').replace('\\', '/')
    
    if not path:
        return False
    
    path_parts = []
    for part in path.split('/'):
        if part == '..':
            if path_parts:
                path_parts.pop()
        elif part and part != '.':
            path_parts.append(part)
    
    resolved_path = '/'.join(path_parts)
    
    for allowed in ALLOWED_PATHS:
        allowed_clean = allowed.strip('/')
        if resolved_path.startswith(allowed_clean):
            return True
    
    bypass_keywords = ['tmp/ctf', 'var/www/html', 'home/user', 'etc']
    if any(resolved_path.startswith(keyword) for keyword in bypass_keywords):
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

@app.route('/debugwiovnwovnruege')
def debug():
    """Debug endpoint to check if files exist"""
    setup_ctf_files()
    
    test_paths = [
        '/tmp/ctf/readme.txt',
        '/home/user/documents/config.txt', 
        '/var/www/html/admin/backup.txt',
        '/home/user/.secret/.flag.txt'
    ]
    
    debug_info = []
    for unix_path in test_paths:
        actual_path = get_ctf_path(unix_path)
        exists = os.path.exists(actual_path)
        debug_info.append(f"Unix: {unix_path}")
        debug_info.append(f"Actual: {actual_path}")
        debug_info.append(f"Exists: {exists}")
        if exists and os.path.isfile(actual_path):
            try:
                with open(actual_path, 'r') as f:
                    content = f.read(100)
                debug_info.append(f"Content preview: {content[:50]}...")
            except:
                debug_info.append("Content: Error reading")
        debug_info.append("-" * 40)
    
    test_traversal = "var/www/html/../../../home/user/.secret/.flag.txt"
    resolved_test = get_ctf_path(test_traversal)
    debug_info.append(f"Test traversal: {test_traversal}")
    debug_info.append(f"Resolved to: {resolved_test}")
    debug_info.append(f"Exists: {os.path.exists(resolved_test)}")
    debug_info.append("-" * 40)
    
    secret_dir = get_ctf_path('/home/user/.secret')
    debug_info.append(f"Secret dir path: {secret_dir}")
    debug_info.append(f"Secret dir exists: {os.path.exists(secret_dir)}")
    if os.path.exists(secret_dir):
        try:
            secret_files = os.listdir(secret_dir)
            debug_info.append(f"Secret dir contents: {secret_files}")
        except Exception as e:
            debug_info.append(f"Error listing secret dir: {e}")
    debug_info.append("-" * 40)
    
    return render_template('result.html', content='\n'.join(debug_info))

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
                    
                    decoded_path = decoded_path.replace('\\', '/')
                    
                    check_path = decoded_path.lstrip('/')
                    
                    logger.info(f"Original path: {file_part}")
                    logger.info(f"Decoded path: {decoded_path}")
                    logger.info(f"Check path: {check_path}")
                    logger.info(f"Path validation result: {is_safe_path(check_path)}")
                    
                    if not is_safe_path(check_path):
                        content = f"Access denied: Path '{decoded_path}' is not in allowed directories.\nAllowed: {', '.join(ALLOWED_PATHS)}"
                    else:
                        try:
                            target_path = get_ctf_path(decoded_path)
                            
                            logger.info(f"Final target path: {target_path}")
                            
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
                                content = f"File not found: {decoded_path}\nResolved to: {target_path}\nChecking if path exists: {os.path.exists(target_path)}"

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