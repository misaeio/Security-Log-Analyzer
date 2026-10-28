import os

def create_sample_logs():
    os.makedirs("logs", exist_ok=True)
    
    # 1. Auth log with brute force & malformed lines
    auth_data = """Oct 27 10:00:01 server sshd[1001]: Failed password for invalid user admin from 192.168.1.105 port 4421 ssh2
Oct 27 10:00:05 server sshd[1002]: Failed password for invalid user admin from 192.168.1.105 port 4422 ssh2
Oct 27 10:00:10 server sshd[1003]: Failed password for invalid user admin from 192.168.1.105 port 4423 ssh2
Oct 27 10:00:15 server sshd[1004]: Failed password for invalid user admin from 192.168.1.105 port 4424 ssh2
Oct 27 10:00:20 server sshd[1005]: Failed password for invalid user admin from 192.168.1.105 port 4425 ssh2
Oct 27 10:00:25 server sshd[1006]: Accepted password for root from 192.168.1.50 port 5512 ssh2
THIS IS A MALFORMED LOG LINE THAT SHOULD NOT CRASH THE SYSTEM
"""

    # 2. Web log with SQLi and Directory Traversal
    web_data = """192.168.1.200 - - [27/Oct/2026:10:15:32 +0000] "GET /index.php HTTP/1.1" 200 1420
10.0.0.85 - - [27/Oct/2026:10:16:01 +0000] "GET /login.php?user=admin' UNION SELECT NULL,password FROM users-- HTTP/1.1" 500 230
10.0.0.85 - - [27/Oct/2026:10:17:11 +0000] "GET /download?file=/etc/passwd HTTP/1.1" 403 512
"""

    with open("logs/auth_sample.log", "w") as f:
        f.write(auth_data)
        
    with open("logs/web_access.log", "w") as f:
        f.write(web_data)

    print("[+] Synthetic logs created under logs/")