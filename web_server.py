"""
web_server.py - Live Web Presentation Server & Python API Bridge for AR-SPECK

AR-SPECK Project Presentation Web Bridge

Starts the live ARSpeckServer on UDP port 5000 and serves an interactive web dashboard
on HTTP port 8000 using standard library http.server (ZERO third-party pip dependencies!).

JSON API Endpoints:
  - GET  /api/status          : Returns server status, client streaming status, log counts, and window state.
  - GET  /api/logs            : Returns list of real-time server log entries.
  - POST /api/server_toggle   : Toggles UDP server ON / OFF.
  - POST /api/client_toggle   : Toggles continuous UDP client traffic stream ON / OFF.
  - POST /api/send            : Sends a single UDP packet ('position' or 'score').
  - POST /api/attack          : Fires an attack ('tamper', 'replay', 'spoof') over UDP.
  - POST /api/burst           : Sends a 20-packet traffic burst.
  - POST /api/reset           : Clears server logs and resets sliding window state.
"""

import http.server
import socketserver
import json
import socket
import threading
import time
import os
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from server import ARSpeckServer
from client import ARSpeckClient
from attacks.packet_editor import run_packet_editor_attack
from attacks.replay import run_replay_attack
from attacks.spoofed_sender import run_spoofed_sender_attack
from tiering import TIER_ROUNDS

UDP_PORT = 5000
HTTP_PORT = 8000
KEY = bytes.fromhex("0001020308090a0b1011121318191a1b")

speck_server = ARSpeckServer(host="127.0.0.1", port=UDP_PORT, key=KEY)
speck_client = None

# Continuous client traffic background thread control
client_streaming = False
client_thread = None


def client_streaming_loop():
    """Background loop sending continuous game packets while client_streaming is True."""
    global speck_client, client_streaming
    count = 0
    while client_streaming:
        if speck_client is None:
            speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
            
        pkt_type = "score" if (count % 10 == 0) else "position"
        try:
            speck_client.send_game_packet(packet_type=pkt_type)
            count += 1
        except Exception as e:
            print(f"Streaming client error: {e}")
            break
            
        time.sleep(0.05)  # ~20 Hz tick rate


class ARSpeckHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler serving static frontend files from /web
    and providing JSON API endpoints for live simulation.
    """
    def __init__(self, *args, **kwargs):
        web_dir = os.path.join(os.path.dirname(__file__), "web")
        super().__init__(*args, directory=web_dir, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == "/api/status":
            self._send_json_response(self._get_status_data())
        elif path == "/api/logs":
            with speck_server.lock:
                logs_copy = list(speck_server.logs)
            self._send_json_response({"logs": logs_copy})
        else:
            super().do_GET()

    def do_POST(self):
        global speck_client, client_streaming, client_thread
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b""
        
        try:
            body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body_json = {}

        if path == "/api/server_toggle":
            action = body_json.get("action", "toggle")
            if action == "off" or (action == "toggle" and speck_server.is_running):
                speck_server.stop()
                msg = "UDP Server stopped (OFFLINE)"
            else:
                speck_server.start()
                msg = "UDP Server started (ONLINE)"
            self._send_json_response({"status": "success", "server_running": speck_server.is_running, "message": msg})

        elif path == "/api/client_toggle":
            action = body_json.get("action", "toggle")
            if action == "off" or (action == "toggle" and client_streaming):
                client_streaming = False
                msg = "Continuous Client Traffic stopped (IDLE)"
            else:
                if not speck_server.is_running:
                    speck_server.start()
                client_streaming = True
                client_thread = threading.Thread(target=client_streaming_loop, daemon=True)
                client_thread.start()
                msg = "Continuous Client Traffic started (~20 Hz UDP stream)"
            self._send_json_response({"status": "success", "client_streaming": client_streaming, "message": msg})

        elif path == "/api/send":
            pkt_type = body_json.get("packet_type", "position")
            if not speck_server.is_running:
                speck_server.start()
                
            if speck_client is None:
                speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
            
            wire = speck_client.send_game_packet(packet_type=pkt_type)
            seq = speck_client.seq_no - 1
            self._send_json_response({
                "status": "success",
                "message": f"Sent {pkt_type} packet (Seq {seq}) over UDP",
                "seq_no": seq,
                "wire_hex": wire.hex()
            })

        elif path == "/api/attack":
            attack_type = body_json.get("attack_type", "tamper")
            if not speck_server.is_running:
                speck_server.start()

            if speck_client is None:
                speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
                
            attack_seq = speck_client.seq_no
            speck_client.seq_no += 10
            
            if attack_type == "tamper":
                seq, name = run_packet_editor_attack(server_port=UDP_PORT, key=KEY, seq_no=attack_seq)
            elif attack_type == "replay":
                seq, name = run_replay_attack(server_port=UDP_PORT, key=KEY, seq_no=attack_seq)
            elif attack_type == "spoof":
                seq, name = run_spoofed_sender_attack(server_port=UDP_PORT, seq_no=attack_seq)
            else:
                self._send_json_response({"error": "Unknown attack type"}, status=400)
                return

            self._send_json_response({
                "status": "success",
                "message": f"Executed attack '{name}' (Seq {seq}) over UDP",
                "seq_no": seq
            })

        elif path == "/api/burst":
            count = int(body_json.get("count", 20))
            if not speck_server.is_running:
                speck_server.start()

            if speck_client is None:
                speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
            sent = speck_client.send_burst(count=count, interval_ms=5.0)
            self._send_json_response({
                "status": "success",
                "message": f"Sent burst of {sent} packets over UDP",
                "count": sent
            })

        elif path == "/api/reset":
            with speck_server.lock:
                speck_server.logs.clear()
                speck_server.client_windows.clear()
            if speck_client:
                speck_client.seq_no = 1
            self._send_json_response({"status": "success", "message": "Server state reset"})
            
        else:
            self._send_json_response({"error": "Not Found"}, status=404)

    def _get_status_data(self) -> dict:
        with speck_server.lock:
            logs = list(speck_server.logs)
            windows = {}
            for addr, win in speck_server.client_windows.items():
                addr_str = f"{addr[0]}:{addr[1]}"
                windows[addr_str] = {
                    "max_seq": win.max_seq,
                    "bitmap_hex": f"0x{win.bitmap:016X}",
                    "bitmap_bin": f"{win.bitmap:064b}"
                }
                
        total = len(logs)
        accepts = sum(1 for e in logs if e["event"] == "accept")
        bad_macs = sum(1 for e in logs if e["reason"] == "bad_mac")
        replays = sum(1 for e in logs if e["reason"] == "replay")
        too_olds = sum(1 for e in logs if e["reason"] == "too_old")

        return {
            "server_running": speck_server.is_running,
            "client_streaming": client_streaming,
            "udp_port": UDP_PORT,
            "total_packets": total,
            "accepted": accepts,
            "bad_mac_drops": bad_macs,
            "replay_drops": replays,
            "too_old_drops": too_olds,
            "windows": windows
        }

    def _send_json_response(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def main():
    print("=" * 80)
    print("      AR-SPECK LIVE PRESENTATION WEB DASHBOARD & UDP BRIDGE        ")
    print("=" * 80)
    
    speck_server.start()
    print(f"[*] ARSpeckServer UDP listening on 127.0.0.1:{UDP_PORT}")
    
    httpd = socketserver.TCPServer(("0.0.0.0", HTTP_PORT), ARSpeckHTTPHandler)
    print(f"[*] Web Dashboard live at: http://localhost:{HTTP_PORT}")
    print("Press Ctrl+C to stop the presentation server.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down presentation server...")
    finally:
        httpd.server_close()
        speck_server.stop()
        if speck_client:
            speck_client.close()
        print("Server stopped cleanly.")


if __name__ == "__main__":
    main()
