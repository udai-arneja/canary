"""
Script to generate test attack data for the dashboard
Run this to populate the database with sample attacks for demo purposes
"""
import requests
import random
import time
from datetime import datetime, timedelta

API_URL = "http://localhost:8000/api/attacks"

WEBSITES = [
    "https://honeypot1.example.com",
    "https://honeypot2.example.com",
    "https://honeypot3.example.com",
    "https://api-test.example.com",
    "https://admin-panel.example.com",
]

VULNERABILITIES = [
    "SQL Injection",
    "XSS (Cross-Site Scripting)",
    "CSRF (Cross-Site Request Forgery)",
    "Path Traversal",
    "Command Injection",
    "SSRF (Server-Side Request Forgery)",
    "XXE (XML External Entity)",
    "Insecure Deserialization",
    "Broken Authentication",
    "Sensitive Data Exposure",
]

ATTACK_VECTORS = [
    "POST /api/login",
    "GET /api/users?id=",
    "POST /upload",
    "GET /admin",
    "POST /api/execute",
    "GET /files/",
    "POST /api/query",
]

def generate_attack():
    """Generate a random attack"""
    base_time = datetime.utcnow() - timedelta(hours=random.randint(0, 24))
    
    attack = {
        "timestamp": (base_time - timedelta(seconds=random.randint(0, 3600))).isoformat(),
        "website_url": random.choice(WEBSITES),
        "vulnerability_type": random.choice(VULNERABILITIES),
        "attack_vector": random.choice(ATTACK_VECTORS),
        "success": random.random() < 0.3,  # 30% success rate
        "payload": f"<script>alert('test')</script>" if random.random() < 0.5 else None,
        "source_ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "user_agent": random.choice([
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "python-requests/2.28.1",
            "curl/7.68.0",
            None
        ]),
        "response_code": random.choice([200, 403, 404, 500, 302])
    }
    
    return attack

def send_attacks(count=50):
    """Send multiple attacks to the API"""
    print(f"Sending {count} test attacks...")
    
    for i in range(count):
        attack = generate_attack()
        try:
            response = requests.post(API_URL, json=attack)
            if response.status_code == 200:
                print(f"✓ Attack {i+1}/{count} sent")
            else:
                print(f"✗ Attack {i+1}/{count} failed: {response.status_code}")
        except Exception as e:
            print(f"✗ Error sending attack {i+1}: {e}")
        
        # Small delay to simulate real-time
        time.sleep(0.1)
    
    print(f"\n✓ Sent {count} attacks successfully!")

if __name__ == "__main__":
    import sys
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    send_attacks(count)

