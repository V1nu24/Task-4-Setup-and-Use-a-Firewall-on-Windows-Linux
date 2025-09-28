
# Firewall Server Handler
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import json
import re
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall.log'),
        logging.StreamHandler()
    ]
)

host = "localhost"
port = 8000

# Security configuration
MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB limit
MAX_HEADER_SIZE = 8192  # 8KB limit
RATE_LIMIT_REQUESTS = 100  # Max requests per IP per minute
REQUEST_TIMEOUT = 30  # Seconds

# Rate limiting storage (in production, use Redis or database)
request_counts = {}

#########
# Handle the response here 
def block_request(self):
    """Block malicious requests and log the attempt"""
    try:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        logging.warning(f"BLOCKED REQUEST from {client_ip}: {self.command} {self.path}")
        
        self.send_response(403)  # Forbidden
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Firewall-Status", "blocked")
        self.end_headers()
        
        response_data = {
            "status": "blocked", 
            "reason": "Malicious request detected",
            "timestamp": datetime.now().isoformat(),
            "request_id": f"{datetime.now().timestamp()}"
        }
        self.wfile.write(json.dumps(response_data).encode('utf-8'))
        
    except Exception as e:
        logging.error(f"Error in block_request: {e}")

def handle_request(self):
    """Allow legitimate requests"""
    try:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        logging.info(f"ALLOWED REQUEST from {client_ip}: {self.command} {self.path}")
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Firewall-Status", "allowed")
        self.end_headers()
        
        response_data = {
            "status": "allowed",
            "message": "Request processed successfully",
            "timestamp": datetime.now().isoformat(),
            "server": "Telstra Firewall Server v1.0"
        }
        self.wfile.write(json.dumps(response_data).encode('utf-8'))
        
    except Exception as e:
        logging.error(f"Error in handle_request: {e}")

def check_rate_limit(self):
    """Simple rate limiting check"""
    try:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        current_time = datetime.now().timestamp()
        
        # Clean old entries (older than 1 minute)
        cutoff_time = current_time - 60
        request_counts[client_ip] = [
            req_time for req_time in request_counts.get(client_ip, []) 
            if req_time > cutoff_time
        ]
        
        # Check current count
        if len(request_counts.get(client_ip, [])) >= RATE_LIMIT_REQUESTS:
            logging.warning(f"Rate limit exceeded for {client_ip}")
            return False
            
        # Add current request
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        request_counts[client_ip].append(current_time)
        
        return True
    except Exception as e:
        logging.error(f"Error in rate limiting: {e}")
        return True  # Allow on error

def sanitize_input(text, max_length=1000):
    """Sanitize and validate input text"""
    if not isinstance(text, str):
        return ""
    
    # Truncate if too long
    text = text[:max_length]
    
    # Remove null bytes and control characters
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    
    return text

def is_malicious_request(self):
    """
    Check if the incoming request matches malicious patterns
    Returns True if request should be blocked, False otherwise
    """
    try:
        # Rate limiting check
        if not check_rate_limit(self):
            logging.warning("Request blocked due to rate limiting")
            return True
        
        # Sanitize path
        safe_path = sanitize_input(self.path, 500)
        
        # Check for malicious paths (case-insensitive)
        malicious_paths = [
            "/tomcatwar.jsp",
            "/shell.jsp",
            "/webshell.jsp",
            "/cmd.jsp",
            "/.env",
            "/admin",
            "/manager/html"
        ]
        
        for malicious_path in malicious_paths:
            if malicious_path.lower() in safe_path.lower():
                logging.warning(f"Malicious path detected: {safe_path}")
                return True
        
        # Check for directory traversal attempts
        if "../" in safe_path or "..\\\" in safe_path:
            logging.warning(f"Directory traversal attempt detected: {safe_path}")
            return True
        
        # Check for malicious HTTP headers
        malicious_headers = {
            'suffix': '%>//',
            'c1': 'Runtime',
            'c2': '<%',
            'DNT': '1',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Convert headers to lowercase for case-insensitive comparison
        request_headers = {}
        for k, v in self.headers.items():
            if len(k) > 100 or len(v) > 1000:  # Header size validation
                logging.warning(f"Oversized header detected: {k}")
                return True
            request_headers[k.lower()] = sanitize_input(v.lower())
        
        # Check if request contains suspicious header combinations
        suspicious_count = 0
        detected_headers = []
        
        for header_name, header_value in malicious_headers.items():
            header_name_lower = header_name.lower()
            header_value_lower = header_value.lower()
            
            if header_name_lower in request_headers:
                if header_value_lower in request_headers[header_name_lower]:
                    suspicious_count += 1
                    detected_headers.append(f"{header_name}: {header_value}")
        
        # Block if we detect multiple suspicious headers
        if suspicious_count >= 2:  # Lowered threshold for better detection
            logging.warning(f"Suspicious headers detected: {detected_headers}")
            return True
        
        # Check for malicious User-Agent patterns
        user_agent = request_headers.get('user-agent', '')
        malicious_ua_patterns = [
            'sqlmap',
            'nikto',
            'nessus',
            'burpsuite',
            'nmap',
            'masscan'
        ]
        
        for pattern in malicious_ua_patterns:
            if pattern in user_agent:
                logging.warning(f"Malicious User-Agent detected: {user_agent}")
                return True
        
        # Additional check for URL-encoded malicious content in POST data
        if self.command == 'POST':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                
                # Validate content length
                if content_length > MAX_CONTENT_LENGTH:
                    logging.warning(f"Content length too large: {content_length}")
                    return True
                
                if content_length > 0:
                    post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                    post_data = sanitize_input(post_data, MAX_CONTENT_LENGTH)
                    
                    # Check for JSP/Java code injection patterns
                    malicious_patterns = [
                        'Runtime.getRuntime',
                        'ProcessBuilder',
                        'java.lang.Runtime',
                        'exec(',
                        'cmd.exe',
                        '/bin/sh',
                        'system(',
                        'shell_exec',
                        'eval(',
                        '<script',
                        'javascript:',
                        'vbscript:',
                        'onload=',
                        'onerror='
                    ]
                    
                    post_data_lower = post_data.lower()
                    for pattern in malicious_patterns:
                        if pattern.lower() in post_data_lower:
                            logging.warning(f"Malicious payload detected in POST data: {pattern}")
                            return True
                            
            except ValueError:
                logging.warning("Invalid Content-Length header")
                return True
            except Exception as e:
                logging.error(f"Error reading POST data: {e}")
                return True
        
        return False
        
    except Exception as e:
        logging.error(f"Error in is_malicious_request: {e}")
        return True  # Block on error for security

#########

class ServerHandler(BaseHTTPRequestHandler):
    
    def setup(self):
        """Setup connection with timeout"""
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)
    
    def do_GET(self):
        try:
            if is_malicious_request(self):
                block_request(self)
            else:
                handle_request(self)
        except Exception as e:
            logging.error(f"Error handling GET request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_POST(self):
        try:
            if is_malicious_request(self):
                block_request(self)
            else:
                handle_request(self)
        except Exception as e:
            logging.error(f"Error handling POST request: {e}")
            self.send_error(500, "Internal Server Error")
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        try:
            if is_malicious_request(self):
                self.send_response(403)
            else:
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        except Exception as e:
            logging.error(f"Error handling HEAD request: {e}")
    
    def log_message(self, format, *args):
        """Override default logging to use our logger"""
        try:
            client_ip = self.client_address[0] if self.client_address else "unknown"
            logging.info(f"[{client_ip}] {format % args}")
        except Exception:
            pass  # Ignore logging errors
    
    def version_string(self):
        """Override server version string"""
        return "Telstra-Firewall/1.0"

if __name__ == "__main__":        
    try:
        server = HTTPServer((host, port), ServerHandler)
        server.timeout = REQUEST_TIMEOUT
        
        print("[+] Telstra Cyber Security Firewall Server")
        print(f"[+] HTTP Web Server running on: {host}:{port}")
        print("[+] Firewall rules active:")
        print("    - Blocking malicious paths (tomcatwar.jsp, shell.jsp, etc.)")
        print("    - Monitoring suspicious header combinations")
        print("    - Scanning POST data for code injection patterns")
        print("    - Rate limiting enabled (100 req/min per IP)")
        print("    - Directory traversal protection")
        print("    - Malicious User-Agent detection")
        print(f"[+] Logging to: firewall.log")
        print("[+] Press Ctrl+C to stop")
        
        logging.info("Firewall server started successfully")
        
        server.serve_forever()
        
    except KeyboardInterrupt:
        print("\n[+] Shutdown signal received")
        logging.info("Server shutdown initiated by user")
    except Exception as e:
        print(f"[!] Server error: {e}")
        logging.error(f"Server startup error: {e}")
    finally:
        try:
            server.server_close()
            logging.info("Server stopped successfully")
        except:
            pass
        
        print("[+] Server terminated. Exiting...")
        exit(0)