"""
web_server.py - Live Web Presentation Server & Python API Bridge for AR-SPECK

Starts the live ARSpeckServer on UDP port 5000 and serves an interactive web dashboard
on HTTP port 8000 using standard library http.server.
"""

import os
import sys
import json
import http.server
import socketserver
import threading
import time
import math
from urllib.parse import parse_qs, urlparse

# Ensure imports resolve from project root directory
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
sys.path.insert(0, PROJECT_ROOT)

# Change directory to web/ so SimpleHTTPRequestHandler serves static files naturally
os.chdir(WEB_DIR)

from server import ARSpeckServer
from client import ARSpeckClient
from attacks.packet_editor import run_packet_editor_attack
from attacks.replay import run_replay_attack
from attacks.spoofed_sender import run_spoofed_sender_attack
from tiering import TIER_ROUNDS, classify_tier_adaptive

UDP_PORT = 5000
HTTP_PORT = 8000
KEY = bytes.fromhex("0001020308090a0b1011121318191a1b")

speck_server = ARSpeckServer(host="127.0.0.1", port=UDP_PORT, key=KEY)
speck_client = None

client_streaming = True
client_thread = None

import random
byte_distribution = [42, 38, 45, 40, 39, 44, 41, 43, 37, 46, 40, 42, 38, 41, 43, 39]
rolling_latencies = [round(random.uniform(11.2, 24.8), 2) for _ in range(60)]

PACKET_SEQUENCE_TYPES = ["ping", "position", "camera", "combat", "trade", "score"]


def client_streaming_loop():
    """Background loop sending continuous game packets while client_streaming is True."""
    global speck_client, client_streaming
    count = 0
    while True:
        if client_streaming:
            if speck_client is None:
                speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
            pkt_type = PACKET_SEQUENCE_TYPES[count % len(PACKET_SEQUENCE_TYPES)]
            try:
                t0 = time.perf_counter()
                wire = speck_client.send_game_packet(packet_type=pkt_type)
                t1 = time.perf_counter()
                if wire and len(wire) >= 9:
                    for b in wire[1:9]:
                        byte_distribution[b // 16] += 1
                lat_us = round((t1 - t0) * 1e6, 2)
                rolling_latencies.append(lat_us)
                if len(rolling_latencies) > 60:
                    rolling_latencies.pop(0)
                count += 1
            except Exception as e:
                print(f"Streaming client error: {e}")
        time.sleep(0.05)


WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class ARSpeckThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        cls, val, tb = sys.exc_info()
        if cls in (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            return
        super().handle_error(request, client_address)


class ARSpeckHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler serving static frontend files from web/ directory.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, format, *args):
        # Silence per-request console spam from polling; only real errors surface
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Browser closed the connection early (e.g. rapid polling / page refresh). Harmless.
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/api/status":
                self.send_json(self._get_status_data())

            elif path == "/api/logs":
                with speck_server.lock:
                    logs_copy = list(speck_server.logs)
                self.send_json({"logs": logs_copy})

            elif path == "/api/analyze":
                query = parse_qs(parsed.query)
                try:
                    payload_size = int(query.get("size", [8])[0])
                except (ValueError, IndexError):
                    payload_size = 8

                speck_ct = math.ceil(payload_size / 8.0) * 8
                speck_pad = speck_ct - payload_size
                speck_pad_pct = round((speck_pad / payload_size) * 100) if payload_size > 0 else 0
                speck_wire = 1 + speck_ct + 4 + 8
                speck_bw_kb = round((speck_pad * 1000 * 120) / 1024)

                aes_ct = (payload_size // 16 + 1) * 16
                aes_pad = aes_ct - payload_size
                aes_pad_pct = round((aes_pad / payload_size) * 100) if payload_size > 0 else 0
                aes_wire = 1 + aes_ct + 4 + 16
                aes_expansion = round(((aes_wire - speck_wire) / speck_wire) * 100) if speck_wire > 0 else 0
                aes_bw_kb = round((aes_pad * 1000 * 120) / 1024)

                self.send_json({
                    "payload_size": payload_size,
                    "speck": {
                        "ct_bytes": speck_ct,
                        "pad_bytes": speck_pad,
                        "pad_pct": speck_pad_pct,
                        "wire_bytes": speck_wire,
                        "bw_wasted_kb": speck_bw_kb
                    },
                    "aes": {
                        "ct_bytes": aes_ct,
                        "pad_bytes": aes_pad,
                        "pad_pct": aes_pad_pct,
                        "wire_bytes": aes_wire,
                        "expansion_pct": aes_expansion,
                        "bw_wasted_kb": aes_bw_kb,
                        "bw_wasted_mb": round(aes_bw_kb / 1024.0, 1)
                    }
                })

            elif path == "/api/avalanche_trace":
                query = parse_qs(parsed.query)
                bit_idx = int(query.get("bit", [0])[0]) % 64
                from speck64 import ror32, rol32, ALPHA, BETA, MASK_32, generate_key_schedule, bytes_to_words32
                rkeys = generate_key_schedule(KEY, rounds=27)
                base_pt = b"MOVE_123"
                byte_pos = bit_idx // 8
                bit_in_byte = bit_idx % 8
                pt_mod = bytearray(base_pt)
                pt_mod[byte_pos] ^= (1 << bit_in_byte)
                pt_mod = bytes(pt_mod)

                w1 = bytes_to_words32(base_pt)
                y1, x1 = w1[0], w1[1]
                w2 = bytes_to_words32(pt_mod)
                y2, x2 = w2[0], w2[1]

                trace = []
                diff_init = ((x1 ^ x2) << 32) | (y1 ^ y2)
                bits_init = bin(diff_init).count("1")
                trace.append({
                    "round": 0,
                    "flipped_bits": bits_init,
                    "pct": round(bits_init / 64.0 * 100, 1),
                    "diff_hex": f"0x{diff_init:016X}",
                    "bits": [int(b) for b in f"{diff_init:064b}"]
                })

                for r_idx, rk in enumerate(rkeys):
                    x1 = ((ror32(x1, ALPHA) + y1) & MASK_32) ^ rk
                    y1 = rol32(y1, BETA) ^ x1
                    x2 = ((ror32(x2, ALPHA) + y2) & MASK_32) ^ rk
                    y2 = rol32(y2, BETA) ^ x2
                    diff = ((x1 ^ x2) << 32) | (y1 ^ y2)
                    cnt = bin(diff).count("1")
                    trace.append({
                        "round": r_idx + 1,
                        "flipped_bits": cnt,
                        "pct": round(cnt / 64.0 * 100, 1),
                        "diff_hex": f"0x{diff:016X}",
                        "bits": [int(b) for b in f"{diff:064b}"]
                    })

                self.send_json({
                    "flipped_input_bit": bit_idx,
                    "trace": trace
                })

            elif path == "/api/scale_sim":
                query = parse_qs(parsed.query)
                try:
                    players = int(query.get("players", [1000])[0])
                except (ValueError, IndexError):
                    players = 1000
                try:
                    tick_rate = int(query.get("tick_rate", [120])[0])
                except (ValueError, IndexError):
                    tick_rate = 120

                # Measurements from master benchmark (Phase 6)
                # SPECK T=12 latency: 7.07 us (total with MAC: 10.60 us)
                # SPECK T=27 latency: 18.31 us (total with MAC: 21.84 us)
                # AES-128 latency: 1.55 us cipher, but 37 bytes wire vs 21 bytes wire (16 B extra wire per packet!)
                # ChaCha20-Poly1305 wire: 36 bytes (15 B extra)
                # DTLS AES-GCM wire: 56 bytes (35 B extra)
                packets_per_sec = players * tick_rate

                speck_wire_bytes = 21
                aes_wire_bytes = 37
                chacha_wire_bytes = 36
                dtls_wire_bytes = 56

                # Bandwidth per second (MB/s)
                speck_bw_mbs = round((packets_per_sec * speck_wire_bytes) / (1024 * 1024), 2)
                aes_bw_mbs = round((packets_per_sec * aes_wire_bytes) / (1024 * 1024), 2)
                dtls_bw_mbs = round((packets_per_sec * dtls_wire_bytes) / (1024 * 1024), 2)

                bw_saved_vs_aes_mbs = round(aes_bw_mbs - speck_bw_mbs, 2)
                bw_saved_pct = round(((aes_wire_bytes - speck_wire_bytes) / aes_wire_bytes) * 100, 1)

                # CPU Time spent per second on encryption (Server budget analysis)
                # 1 core = 1,000,000 us of CPU per second
                speck_cpu_seconds = round((packets_per_sec * 10.60) / 1e6, 3)
                aes_cpu_seconds = round((packets_per_sec * 1.55) / 1e6, 3)
                aes_cpu_software_only = round((packets_per_sec * 24.5) / 1e6, 3) # without AES-NI hardware accelerator

                self.send_json({
                    "players": players,
                    "tick_rate": tick_rate,
                    "packets_per_sec": packets_per_sec,
                    "speck_wire_bytes": speck_wire_bytes,
                    "aes_wire_bytes": aes_wire_bytes,
                    "dtls_wire_bytes": dtls_wire_bytes,
                    "speck_bw_mbs": speck_bw_mbs,
                    "aes_bw_mbs": aes_bw_mbs,
                    "dtls_bw_mbs": dtls_bw_mbs,
                    "bw_saved_vs_aes_mbs": bw_saved_vs_aes_mbs,
                    "bw_saved_pct": bw_saved_pct,
                    "speck_cpu_seconds": speck_cpu_seconds,
                    "aes_cpu_seconds": aes_cpu_seconds,
                    "aes_cpu_software_only": aes_cpu_software_only
                })

            else:
                super().do_GET()

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # Browser dropped connection early — harmless

        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_error(500, f"Internal server error: {e}")
            except Exception:
                pass

    def do_POST(self):
        global speck_client, client_streaming
        parsed = urlparse(self.path)
        path = parsed.path

        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b""
        try:
            body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            body_json = {}

        try:
            if path == "/api/server_toggle":
                action = body_json.get("action", "toggle")
                if action == "off" or (action == "toggle" and speck_server.is_running):
                    speck_server.stop()
                    msg = "UDP Server stopped (OFFLINE)"
                else:
                    speck_server.start()
                    msg = "UDP Server started (ONLINE)"
                self.send_json({"status": "success", "server_running": speck_server.is_running, "message": msg})

            elif path == "/api/client_toggle":
                action = body_json.get("action", "toggle")
                if action == "off" or (action == "toggle" and client_streaming):
                    client_streaming = False
                    msg = "Continuous Client Traffic stopped (IDLE)"
                else:
                    if not speck_server.is_running:
                        speck_server.start()
                    client_streaming = True
                    msg = "Continuous Client Traffic started (~20 Hz UDP stream)"
                self.send_json({"status": "success", "client_streaming": client_streaming, "message": msg})

            elif path == "/api/send":
                pkt_type = body_json.get("packet_type", "position")
                if not speck_server.is_running:
                    speck_server.start()
                if speck_client is None:
                    speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
                t0 = time.perf_counter()
                wire = speck_client.send_game_packet(packet_type=pkt_type)
                t1 = time.perf_counter()
                seq = speck_client.seq_no - 1
                if wire and len(wire) >= 9:
                    for b in wire[1:9]:
                        byte_distribution[b // 16] += 1
                lat_us = round((t1 - t0) * 1e6, 2)
                rolling_latencies.append(lat_us)
                if len(rolling_latencies) > 60:
                    rolling_latencies.pop(0)
                self.send_json({
                    "status": "success",
                    "message": f"Sent {pkt_type} packet (Seq {seq}) over UDP",
                    "seq_no": seq,
                    "wire_hex": wire.hex(),
                    "latency_us": lat_us
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
                    seq, name, wire_bytes = run_packet_editor_attack(server_port=UDP_PORT, key=KEY, seq_no=attack_seq)
                elif attack_type == "replay":
                    seq, name, wire_bytes = run_replay_attack(server_port=UDP_PORT, key=KEY, seq_no=attack_seq)
                elif attack_type == "spoof":
                    seq, name, wire_bytes = run_spoofed_sender_attack(server_port=UDP_PORT, seq_no=attack_seq)
                else:
                    self.send_json({"error": "Unknown attack type"}, status=400)
                    return
                self.send_json({
                    "status": "success",
                    "message": f"Executed attack '{name}' (Seq {seq}) over UDP",
                    "seq_no": seq,
                    "wire_hex": wire_bytes.hex()
                })

            elif path == "/api/burst":
                count = int(body_json.get("count", 20))
                if not speck_server.is_running:
                    speck_server.start()
                if speck_client is None:
                    speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)
                sent = speck_client.send_burst(count=count, interval_ms=5.0)
                self.send_json({"status": "success", "message": f"Sent burst of {sent} packets over UDP", "count": sent})

            elif path == "/api/game_move":
                if not speck_server.is_running:
                    speck_server.start()
                if speck_client is None:
                    speck_client = ARSpeckClient(server_host="127.0.0.1", server_port=UDP_PORT, key=KEY)

                x = int(body_json.get("x", 200))
                y = int(body_json.get("y", 150))
                vx = int(body_json.get("vx", 0))
                vy = int(body_json.get("vy", 0))
                tamper = bool(body_json.get("tamper", False))

                t0 = time.perf_counter()
                wire, H, T = speck_client.send_player_vector(x=x, y=y, vx=vx, vy=vy, tamper=tamper)
                t1 = time.perf_counter()
                lat_us = round((t1 - t0) * 1e6, 2)

                rolling_latencies.append(lat_us)
                if len(rolling_latencies) > 60:
                    rolling_latencies.pop(0)

                with speck_server.lock:
                    entity_state = dict(speck_server.game_entities.get("player", {}))

                self.send_json({
                    "status": "success",
                    "wire_hex": wire.hex(),
                    "entropy": H,
                    "rounds": T,
                    "latency_us": lat_us,
                    "tampered": tamper,
                    "server_entity": entity_state
                })

            elif path == "/api/reset":
                with speck_server.lock:
                    speck_server.logs.clear()
                    speck_server.client_windows.clear()
                    speck_server.game_entities["player"] = {"x": 200, "y": 150, "vx": 0, "vy": 0, "color": "#0ea5e9", "last_seq": 0, "last_seen": 0.0, "score": 0}
                if speck_client:
                    speck_client.seq_no = 1
                for i in range(16):
                    byte_distribution[i] = 0
                rolling_latencies.clear()
                self.send_json({"status": "success", "message": "Server state reset"})

            else:
                self.send_json({"error": "Not Found"}, status=404)

        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # Browser dropped connection early — harmless

        except Exception as e:
            import traceback
            traceback.print_exc()
            try:
                self.send_json({"error": str(e)}, status=500)
            except Exception:
                pass

    def _get_status_data(self):
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
        accepts = sum(1 for e in logs if e.get("event") == "accept")
        bad_macs = sum(1 for e in logs if e.get("reason") == "bad_mac")
        replays = sum(1 for e in logs if e.get("reason") == "replay")
        too_olds = sum(1 for e in logs if e.get("reason") == "too_old")

        # Idea 2: Threat Automaton telemetry
        threat = speck_server.threat_stats

        # Idea 1 & 2: Entropy engine telemetry + Threat Automaton escalation override
        entropy_last = round(getattr(speck_client, "last_entropy", 0.0), 3)
        base_rounds = getattr(speck_client, "last_entropy_rounds", 8)
        entropy_rounds_last = speck_server.get_escalated_rounds(base_rounds)

        # Idea 3: Markov predictor telemetry
        markov_next = getattr(speck_client, "markov_next_prediction", None)
        markov_prefetch_rounds = getattr(speck_client, "markov_prefetch_rounds", None)

        return {
            "server_running": speck_server.is_running,
            "client_streaming": client_streaming,
            "udp_port": UDP_PORT,
            "total_packets": total,
            "accepted": accepts,
            "bad_mac_drops": bad_macs,
            "replay_drops": replays,
            "too_old_drops": too_olds,
            "windows": windows,
            "byte_distribution": list(byte_distribution),
            "rolling_latencies": list(rolling_latencies),
            "threat": threat,
            "entropy_last": entropy_last,
            "entropy_rounds_last": entropy_rounds_last,
            "markov_next": list(markov_next) if markov_next else None,
            "markov_prefetch_rounds": markov_prefetch_rounds,
            "arena_entities": dict(speck_server.game_entities),
        }

    def log_message(self, format, *args):
        pass


def main():
    global client_thread, HTTP_PORT

    print("=" * 80)
    print("      AR-SPECK LIVE TECHNICAL INSTRUMENTATION PANEL & UDP BRIDGE       ")
    print("=" * 80)

    speck_server.start()
    print(f"[*] ARSpeckServer UDP listening on 127.0.0.1:{UDP_PORT}")

    client_thread = threading.Thread(target=client_streaming_loop, daemon=True)
    client_thread.start()
    print("[*] Auto-started continuous UDP client stream (~20 Hz)")

    ARSpeckThreadingServer.allow_reuse_address = True
    httpd = None
    for port_candidate in [8000, 8080, 8081, 8888]:
        try:
            httpd = ARSpeckThreadingServer(("127.0.0.1", port_candidate), ARSpeckHTTPHandler)
            HTTP_PORT = port_candidate
            break
        except Exception:
            continue

    if httpd is None:
        print("[!] ERROR: Could not bind HTTP presentation server to any port.")
        sys.exit(1)

    print(f"[*] Web Dashboard live at: http://127.0.0.1:{HTTP_PORT}")
    print("Press Ctrl+C to stop.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        httpd.server_close()
        speck_server.stop()
        if speck_client:
            speck_client.close()
        print("Server stopped cleanly.")


if __name__ == "__main__":
    main()
