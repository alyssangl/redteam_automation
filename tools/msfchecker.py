#!/usr/bin/env python3
import time
import argparse
import http.client
import ssl
import sys
import msgpack

# --- CONFIGURATION ---
MSF_HOST = "192.168.34.6"  # 請確認這是你 Kali 的 IP
MSF_PORT = 55553
MSF_USER = "kali"
MSF_PASS = "kali"  # 記得改成你的密碼


class MsfRpcClient:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.token = None
        self.headers = {"Content-type": "binary/message-pack"}
        self.context = ssl._create_unverified_context()
        self.conn = http.client.HTTPSConnection(self.host, self.port, context=self.context)

    def decode_bytes(self, value):
        """Helper to decode bytes to string safely"""
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        return str(value)

    def rpc_call(self, method, *args):
        if method != "auth.login" and not self.token:
            print("[-] Error: Not authenticated.")
            sys.exit(1)

        call_args = [method]
        if self.token and method != "auth.login":
            call_args.append(self.token)
        call_args.extend(args)

        try:
            payload = msgpack.packb(call_args)
            self.conn.request("POST", "/api/", payload, self.headers)
            response = self.conn.getresponse()
            # 這裡加入了 strict_map_key=False 修正你的報錯
            return msgpack.unpackb(response.read(), strict_map_key=False)
        except Exception as e:
            print(f"[-] RPC Connection Failed: {e}")
            sys.exit(1)

    def login(self):
        res = self.rpc_call("auth.login", self.user, self.password)
        if res.get(b'result') == b'success':
            self.token = res[b'token']
            return True
        return False

    def list_sessions(self):
        sessions = self.rpc_call("session.list")

        if not sessions:
            print("[*] No active sessions found.")
            return

        # 定義輸出的表頭格式
        # ID | IP Address | Type | Exploit Used | Info
        header = f"{'ID':<4} | {'Target IP':<22} | {'Type':<12} | {'Exploit / Payload':<30} | {'Extra Info'}"
        print("-" * 110)
        print(header)
        print("-" * 110)

        for sid, details in sessions.items():
            # 1. 解析 ID
            sid_str = str(sid)

            # 2. 解析 IP (Tunnel Peer) - 這是最重要的識別資訊
            peer = self.decode_bytes(details.get(b'tunnel_peer', b'Unknown'))
            # 為了美觀，去掉 IP 後面太長的箭頭 (如果有的話)
            if ' -> ' in peer:
                peer = peer.split(' -> ')[0]  # 只拿 Remote IP

            # 3. 解析類型 (Meterpreter vs Shell)
            s_type = self.decode_bytes(details.get(b'type', b'unknown'))

            # 4. 解析是透過哪個 Exploit 打進去的
            exploit = self.decode_bytes(details.get(b'via_exploit', b'Manual'))
            if exploit == "Manual":  # 如果沒有 exploit，嘗試顯示 payload
                exploit = self.decode_bytes(details.get(b'via_payload', b'Manual/Handler'))
            # 縮短一下顯示
            if len(exploit) > 28: exploit = "..." + exploit[-25:]

            # 5. 解析詳細資訊 (Info)
            s_info = self.decode_bytes(details.get(b'info', b''))
            if not s_info and s_type == 'shell':
                s_info = "(Raw Shell - No System Info)"
            elif not s_info:
                s_info = "(No Info)"

            print(f"{sid_str:<4} | {peer:<22} | {s_type:<12} | {exploit:<30} | {s_info}")

    def open_session(self, session_id):
        print(f"[*] interacting with Session {session_id} (Ctrl+C to exit)...")
        sessions = self.rpc_call("session.list")

        target_details = None
        # 尋找對應 ID (處理 int/str 差異)
        for sid, details in sessions.items():
            if str(sid) == str(session_id):
                target_details = details
                break

        if not target_details:
            print(f"[-] Session {session_id} not found.")
            return

        stype = self.decode_bytes(target_details.get(b'type', b''))

        if 'meterpreter' in stype:
            write_cmd = "session.meterpreter_write"
            read_cmd = "session.meterpreter_read"
            print(f"[*] Type: Meterpreter (Smart Shell)")
        else:
            write_cmd = "session.shell_write"
            read_cmd = "session.shell_read"
            print(f"[*] Type: Raw Shell (Dumb Shell)")

        try:
            while True:
                user_input = input(f"Session {session_id} > ")
                if user_input.lower() in ['exit', 'quit']:
                    break

                if 'shell' in stype: user_input += "\n"

                self.rpc_call(write_cmd, session_id, user_input)
                time.sleep(1)

                output_pack = self.rpc_call(read_cmd, session_id)
                data = self.decode_bytes(output_pack.get(b'data', b''))

                if data:
                    print(data)

        except KeyboardInterrupt:
            print("\n[*] Exiting interaction.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Tool for MSFRPCD")
    parser.add_argument("--list", action="store_true", help="List all active sessions")
    parser.add_argument("--open", type=str, help="Open/Interact with a specific Session ID")

    args = parser.parse_args()

    client = MsfRpcClient(MSF_HOST, MSF_PORT, MSF_USER, MSF_PASS)

    if client.login():
        if args.list:
            client.list_sessions()
        elif args.open:
            client.open_session(args.open)
        else:
            parser.print_help()
    else:
        print("[-] Authentication Failed.")