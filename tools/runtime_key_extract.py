#!/usr/bin/env python3
"""
Noctua-c Runtime AES Key Extraction Pipeline

Automatically extracts FMOD FSB5 encryption keys from running processes
by trying, in order:
  1. Static analysis with Noctua-c modules (existing)
  2. Frida-based runtime tracing (if frida available)
  3. Remote agent protocol (TCP to noctua_agent on target)
  4. ADB-based memory dumping from Android devices
  5. Fallback: generate Frida script for manual use

Usage:
    python3 runtime_key_extract.py <libil2cpp.so> <encrypted.fsb>...
    python3 runtime_key_extract.py --device android <encrypted.fsb>...
    python3 runtime_key_extract.py --agent <host:port> <encrypted.fsb>...
    python3 runtime_key_extract.py --frida-only <process_name>
"""

import argparse
import json
import os
import struct
import subprocess
import socket
import sys
import tempfile
import time
from pathlib import Path

try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

AES_KEY_LEN = 16
NOCTUA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOCTUA_BIN = os.path.join(NOCTUA_DIR, "noctua")
FRIDA_SCRIPT_PATH = os.path.join(NOCTUA_DIR, "tools", "noctua_frida.py")
AGENT_PORT = 47192

FSB5_CODEC_NAMES = {
    0: "None", 1: "PCM8", 2: "PCM16", 3: "PCM24", 4: "PCM32",
    5: "PCMFloat", 6: "GCADPCM", 7: "IMAADPCM", 8: "VAG", 9: "HEVAG",
    10: "XMA", 11: "MPEG", 12: "CELT", 13: "AT9", 14: "XWMA",
    15: "Vorbis", 16: "FADPCM", 17: "Opus",
}


# ============================================================
# Phase 1: Static Analysis
# ============================================================

def run_noctua_module(binary_path, module_name, timeout=120):
    """Run a noctua-c analysis module."""
    if not os.path.exists(NOCTUA_BIN):
        return f"[ERROR] noctua binary not found at {NOCTUA_BIN}"

    try:
        result = subprocess.run(
            [NOCTUA_BIN, binary_path, module_name],
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Module {module_name} timed out"
    except Exception as e:
        return f"[ERROR] {e}"


def extract_hex_keys(text):
    """Extract 32-hex-char sequences from text as potential keys."""
    import re
    keys = set()
    hex32 = re.compile(r'(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])')
    for match in hex32.finditer(text):
        keys.add(match.group(1).lower())
    return sorted(keys)


def static_analysis(binary_path, fsb_files):
    """Run static analysis: extract key candidates from binary."""
    print("\n" + "=" * 60)
    print("[Phase 1] Static Analysis (Noctua-c modules)")
    print("=" * 60)

    if not os.path.exists(binary_path):
        print(f"  Binary not found: {binary_path}")
        return []

    all_keys = set()

    modules = ["aes_key_tracer", "aes_emulator", "aes_key_extract", "il2cpp_dumper"]
    for mod in modules:
        print(f"  Running module: {mod}...")
        output = run_noctua_module(binary_path, mod)
        keys = extract_hex_keys(output)
        if keys:
            print(f"    Found {len(keys)} key candidate(s)")
            all_keys.update(keys)
        else:
            print(f"    No keys found")

    if all_keys:
        print(f"\n  Total unique candidates from static analysis: {len(all_keys)}")
        for k in sorted(all_keys):
            print(f"    {k}")

        # Validate against FSB files
        valid = validate_keys(all_keys, fsb_files)
        if valid:
            return valid

    print("  Static analysis did not find a valid key.")
    return []


# ============================================================
# Phase 2: Frida Runtime Tracer
# ============================================================

def frida_extract(process_name, fsb_files, timeout=60):
    """Use Frida to hook FMOD and capture the encryption key."""
    print("\n" + "=" * 60)
    print("[Phase 2] Frida Runtime Tracer")
    print("=" * 60)

    try:
        import frida
    except ImportError:
        print("  frida module not available. Install with: pip install frida-tools")
        return generate_frida_script(process_name)

    print(f"  Attaching to '{process_name}'...")
    try:
        session = frida.attach(process_name)
    except Exception as e:
        print(f"  Could not attach: {e}")
        try:
            session = frida.attach(process_name)
        except Exception as e2:
            print(f"  Retry failed: {e2}")
            return generate_frida_script(process_name)

    # Build Frida script
    script_code = FRIDA_SCRIPT_TEMPLATE % {"process_name": process_name}
    script = session.create_script(script_code)

    captured_keys = []

    def on_message(message, data):
        if message["type"] == "send":
            print(f"    [Frida] {message['payload']}")
            try:
                payload = message["payload"]
                if "KEY" in payload and ":" in payload:
                    parts = payload.split("KEY: ")
                    if len(parts) > 1:
                        key_hex = parts[1].strip()
                        if len(key_hex) == 32:
                            captured_keys.append(key_hex)
            except Exception:
                pass

    script.on("message", on_message)
    script.load()

    print(f"  Tracing {process_name} for up to {timeout}s...")
    print("  Trigger FMOD audio playback in the game...")

    try:
        for i in range(timeout):
            time.sleep(1)
            if captured_keys:
                break
            if i % 10 == 9:
                print(f"    Waiting... ({i+1}s elapsed)")
    except KeyboardInterrupt:
        print("    Interrupted")

    session.detach()

    if captured_keys:
        print(f"\n  Captured {len(captured_keys)} key(s) via Frida:")
        for k in captured_keys:
            print(f"    {k}")

        valid = validate_keys(set(captured_keys), fsb_files)
        if valid:
            return valid

    print("  Frida did not capture a valid key.")
    return generate_frida_script(process_name)


def generate_frida_script(process_name):
    """Generate a Frida JS script for manual use."""
    print("\n  -> Generating Frida script for manual use")

    from noctua_frida import generate_script
    script = generate_script(process_name)

    out_path = f"frida_noctua_{process_name}.js"
    with open(out_path, "w") as f:
        f.write(script)

    print(f"  Script saved to: {out_path}")
    print(f"  Run manually:  frida -n '{process_name}' -l {out_path}")
    print(f"  Or on Android: frida -U -f '{process_name}' -l {out_path}")
    return None


# ============================================================
# Phase 3: Remote Agent Protocol
# ============================================================

class NoctuaAgentClient:
    """Client for the Noctua remote agent protocol."""

    def __init__(self, host="127.0.0.1", port=AGENT_PORT):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        try:
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"  Connection failed: {e}")
            return False

    def send_cmd(self, cmd):
        if not self.sock:
            return None
        try:
            self.sock.sendall((cmd + "\n").encode())
            return self._read_response()
        except Exception as e:
            print(f"  Command error: {e}")
            return None

    def _read_response(self):
        responses = []
        self.sock.settimeout(3)
        try:
            while True:
                line = self.sock.recv(4096).decode().strip()
                if not line:
                    break
                responses.append(line)
                if line.startswith("ERROR"):
                    break
                if line == "":
                    break
        except socket.timeout:
            pass
        return responses

    def close(self):
        if self.sock:
            try:
                self.send_cmd("QUIT")
            except Exception:
                pass
            self.sock.close()
            self.sock = None


def agent_extract(host, port, fsb_files, process_name=None):
    """Extract key via remote agent protocol."""
    print("\n" + "=" * 60)
    print(f"[Phase 3] Remote Agent ({host}:{port})")
    print("=" * 60)

    client = NoctuaAgentClient(host, port)
    if not client.connect():
        print("  Could not connect to remote agent.")
        return []

    # Ping
    resp = client.send_cmd("PING")
    print(f"  Agent: {resp}")

    # Attach to process
    if not process_name:
        print("  No process specified for agent attach.")
        client.close()
        return []

    if process_name.isdigit():
        attach_cmd = f"PROCESS_ATTACH {process_name}"
    else:
        attach_cmd = f"PROCESS_ATTACH {process_name}"

    resp = client.send_cmd(attach_cmd)
    print(f"  Attach response: {resp}")

    attached = resp and any("OK attached" in r for r in resp)
    if not attached:
        print("  Could not attach to process.")
        client.close()
        return []

    # Get memory regions
    resp = client.send_cmd("MEMORY_REGIONS")
    print(f"  Regions: {resp[0] if resp else 'N/A'}")

    # Search for keys
    resp = client.send_cmd("MEMORY_SEARCH 50")
    print(f"  Search response: {resp}")

    keys = []
    if resp:
        for line in resp:
            if ":" in line and not line.startswith("RESULTS") and not line.startswith("ERROR"):
                parts = line.strip().split(":")
                if len(parts) == 2 and len(parts[1]) == 32:
                    keys.append(parts[1])

    if keys:
        print(f"\n  Found {len(keys)} key candidate(s) via agent:")
        valid = validate_keys(set(keys), fsb_files)
        if valid:
            client.close()
            return valid

    # Also try KEY_SCAN (heap-specific)
    resp = client.send_cmd("KEY_SCAN")
    if resp:
        for line in resp:
            if ":" in line and not line.startswith("RESULTS") and not line.startswith("ERROR"):
                parts = line.strip().split(":")
                if len(parts) == 2 and len(parts[1]) == 32:
                    keys.append(parts[1])

    if keys:
        print(f"\n  Found {len(keys)} key candidate(s) via heap scan:")
        valid = validate_keys(set(keys), fsb_files)
        if valid:
            client.close()
            return valid

    client.close()
    return []


# ============================================================
# Phase 4: ADB Memory Dumping
# ============================================================

def adb_extract(fsb_files, package_name="com.stellarforge.game"):
    """Use ADB to dump process memory from an Android device."""
    print("\n" + "=" * 60)
    print("[Phase 4] ADB Memory Dump")
    print("=" * 60)

    # Check ADB
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True,
                                text=True, timeout=10)
        if "device" not in result.stdout:
            print("  No Android device connected.")
            return []
    except FileNotFoundError:
        print("  ADB not found.")
        return []

    # Get PID
    result = subprocess.run(
        ["adb", "shell", "pidof", package_name],
        capture_output=True, text=True, timeout=10
    )
    pid = result.stdout.strip()
    if not pid:
        print(f"  Process '{package_name}' not running.")
        return []

    print(f"  Found PID: {pid}")

    # Dump memory via /proc/pid/mem
    try:
        out_dir = tempfile.mkdtemp(prefix="noctua_mem_")

        # Get regions first
        result = subprocess.run(
            ["adb", "shell", "cat", f"/proc/{pid}/maps"],
            capture_output=True, text=True, timeout=10
        )
        maps = result.stdout

        # Find heap
        keys = []
        for line in maps.split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            # Focus on heap and writable anonymous regions
            is_heap = "[heap]" in line
            is_anon = "[" not in line or "stack" in line
            if not is_heap and not is_anon:
                continue

            if parts[1][0] != 'r':
                continue

            addr_range = parts[0].split("-")
            if len(addr_range) != 2:
                continue

            start = int(addr_range[0], 16)
            end = int(addr_range[1], 16)
            size = end - start

            if size > 4 * 1024 * 1024:  # Skip regions > 4MB
                continue

            # Dump via ADB
            dump_path = f"/data/local/tmp/noctua_dump_{start:x}.bin"
            subprocess.run(
                ["adb", "shell", f"su -c 'dd if=/proc/{pid}/mem bs=1 skip={start} count={size} of={dump_path}'"],
                capture_output=True, timeout=30
            )

            # Pull and scan
            local_path = os.path.join(out_dir, f"dump_{start:x}.bin")
            subprocess.run(
                ["adb", "pull", dump_path, local_path],
                capture_output=True, timeout=30
            )
            subprocess.run(
                ["adb", "shell", "rm", dump_path],
                capture_output=True
            )

            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    data = f.read()

                for i in range(len(data) - AES_KEY_LEN):
                    chunk = data[i:i + AES_KEY_LEN]
                    if is_aes_key_candidate(chunk):
                        keys.append(chunk.hex())

                os.unlink(local_path)

        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)

        if keys:
            print(f"  Found {len(keys)} candidate(s) via ADB dump")
            valid = validate_keys(set(keys), fsb_files)
            if valid:
                return valid

    except Exception as e:
        print(f"  Error during ADB dump: {e}")

    return []


# ============================================================
# Key Validation
# ============================================================

def validate_keys(key_hexes, fsb_files):
    """Test key candidates against encrypted FSB5 files."""
    if not key_hexes or not fsb_files:
        return []

    valid_keys = []
    for key_hex in sorted(key_hexes):
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            continue

        if len(key) != AES_KEY_LEN:
            continue

        all_valid = True
        for fsb_path in fsb_files:
            if not test_fsb5_key(fsb_path, key):
                all_valid = False
                break

        if all_valid:
            valid_keys.append(key_hex)

    return valid_keys


def test_fsb5_key(fsb_path, key):
    """Test if a key correctly decrypts an FSB5 file."""
    try:
        with open(fsb_path, "rb") as f:
            data = f.read()
    except Exception:
        return False

    if data[:4] != b"FSB5" or len(data) < 20:
        return False

    counter = b'\x00' * 16

    if HAS_CRYPTO:
        cipher = AES.new(key, AES.MODE_ECB)
        ks = cipher.encrypt(counter)
    else:
        ks = manual_aes_encrypt(key, counter)

    ct = data[4:20]
    pt = bytes(a ^ b for a, b in zip(ct, ks))

    if len(pt) < 4:
        return False

    version = struct.unpack('<I', pt[0:4])[0]
    if version not in (0, 1):
        return False

    # Additional header validation
    if len(pt) >= 24:
        num_samp = struct.unpack('<I', pt[4:8])[0]
        hdr_sz = struct.unpack('<I', pt[8:12])[0]
        if not (1 <= num_samp <= 1000) or not (20 <= hdr_sz <= 50000):
            return False

    return True


def is_aes_key_candidate(data):
    """Check if 16 bytes look like an AES key."""
    if len(data) != AES_KEY_LEN:
        return False

    printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
    zeros = sum(1 for b in data if b == 0)
    repeats = sum(1 for i in range(len(data)) for j in range(i + 1, len(data))
                  if data[i] == data[j])

    if printable >= 8 or zeros >= 8 or repeats > 16:
        return False

    entropy = 0
    for b in set(data):
        p = data.count(b) / AES_KEY_LEN
        if p > 0:
            entropy -= p * (p.bit_length())

    return entropy > 0.5


def manual_aes_encrypt(key, block):
    """Minimal AES-128 encrypt for key validation (ECB, 1 block)."""
    AES_SBOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16,
    ]
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    # Key expansion
    w = list(key)
    for i in range(16, 16 * 11):
        temp = list(w[-4:])
        if i % 16 == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 16 - 1]
        w.append(w[-16] ^ temp[0])
        w.append(w[-12] ^ temp[1])
        w.append(w[-8] ^ temp[2])
        w.append(w[-4] ^ temp[3])

    expanded = bytes(w)

    # Single block encrypt (simplified - just Xor RoundKey for validation)
    state = list(block)
    for i in range(16):
        state[i] ^= expanded[i]
    return bytes(state)


# ============================================================
# Decryption Output
# ============================================================

def decrypt_and_show(key_hex, fsb_files):
    """Decrypt FSB5 files with found key and show headers."""
    if not HAS_CRYPTO:
        print("\n  [WARN] pycryptodome not installed, cannot show decryption details")
        return

    key = bytes.fromhex(key_hex)
    for path in fsb_files:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()

        print(f"\n  {name}:")
        print(f"  {'-' * 50}")

        counter = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_ECB)

        for block_idx in range(8):
            ct = data[4 + block_idx * 16: 4 + (block_idx + 1) * 16]
            ks = cipher.encrypt(counter)
            pt = bytes(a ^ b for a, b in zip(ct, ks))
            hex_str = pt.hex()
            ascii_str = ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in pt)
            print(f"    {block_idx * 16:04x}: {hex_str}  {ascii_str}")

        # Parse header
        ct0 = data[4:20]
        ks0 = cipher.encrypt(counter)
        pt0 = bytes(a ^ b for a, b in zip(ct0, ks0))

        if len(pt0) >= 24:
            ver = struct.unpack('<I', pt0[0:4])[0]
            ns = struct.unpack('<I', pt0[4:8])[0]
            hs = struct.unpack('<I', pt0[8:12])[0]
            ds = struct.unpack('<I', pt0[16:20])[0]
            codec = struct.unpack('<I', pt0[20:24])[0]
            codec_name = FSB5_CODEC_NAMES.get(codec, f"Unknown ({codec})")

            print(f"\n    FSB5 Header: ver={ver} samples={ns} hdr_size={hs} "
                  f"data_size={ds} codec={codec_name}")
            if ver in (0, 1) and 1 <= ns <= 1000 and 20 <= hs <= 50000:
                print(f"    >>> VALID FSB5 HEADER <<<")


# ============================================================
# Main Pipeline
# ============================================================

FRIDA_SCRIPT_TEMPLATE = """
'use strict';
const CONFIG = { processName: '%(process_name)s', keyOutputFile: '/data/local/tmp/noctua_key.txt' };
const setEncKeyPtr = Module.findExportByName(null, '_ZN4FMOD6System16setEncryptionKeyEPKhi');
if (setEncKeyPtr) {
    Interceptor.attach(setEncKeyPtr, {
        onEnter: function(args) {
            const keyLen = args[2].toInt32();
            if (keyLen > 0) {
                const keyBytes = Memory.readByteArray(args[1], Math.min(keyLen, 64));
                const keyHex = Array.prototype.map.call(new Uint8Array(keyBytes), b => ('0' + b.toString(16)).slice(-2)).join('');
                send('KEY: ' + keyHex);
                console.log('[Noctua] KEY: ' + keyHex);
            }
        }
    });
    send('Noctua agent loaded on ' + CONFIG.processName);
} else {
    send('setEncryptionKey not found');
}
"""


def main():
    parser = argparse.ArgumentParser(
        description="Noctua-c Runtime AES Key Extraction Pipeline"
    )
    parser.add_argument("target", nargs="?", help="Binary path (libil2cpp.so) or device target")
    parser.add_argument("fsb_files", nargs="*", help="Encrypted FSB5 files to decrypt")
    parser.add_argument("--device", choices=["android"], help="Target device type")
    parser.add_argument("--agent", metavar="HOST:PORT", help="Remote agent address")
    parser.add_argument("--frida-only", metavar="PROCESS", help="Use Frida only")
    parser.add_argument("--process", default="com.stellarforge.game",
                        help="Process name for runtime tracing")
    parser.add_argument("--output", "-o", help="Output file for found key")

    args = parser.parse_args()

    # Determine operation mode
    if args.frida_only:
        frida_extract(args.frida_only, [])
        return

    if args.agent:
        host, _, port_str = args.agent.partition(":")
        port = int(port_str) if port_str else AGENT_PORT
        fsb_files = args.fsb_files
        keys = agent_extract(host, port, fsb_files, args.process)
        if keys:
            save_and_decrypt(keys[0], fsb_files, args.output)
        return

    binary_path = args.target
    fsb_files = args.fsb_files

    if args.device == "android":
        if not fsb_files:
            print("Need FSB files to validate keys. Add them as arguments.")
            return

        keys = adb_extract(fsb_files, args.process)
        if keys:
            save_and_decrypt(keys[0], fsb_files, args.output)
            return

        # Fall back to Frida on Android
        keys = frida_extract(args.process, fsb_files)
        if keys:
            save_and_decrypt(keys, fsb_files, args.output)
            return

        print("\n[FAILED] Could not extract key from Android device.")
        return

    # Standard mode: binary + FSB files
    if not binary_path or not fsb_files:
        print(f"Usage: {sys.argv[0]} <libil2cpp.so> <encrypted.fsb>...")
        print(f"       {sys.argv[0]} --device android <encrypted.fsb>...")
        print(f"       {sys.argv[0]} --agent <host:port> <encrypted.fsb>...")
        sys.exit(1)

    if not os.path.exists(binary_path):
        print(f"Binary not found: {binary_path}")
        sys.exit(1)

    for f in fsb_files:
        if not os.path.exists(f):
            print(f"FSB file not found: {f}")
            sys.exit(1)

    print("=" * 60)
    print("Noctua-c Runtime Key Extraction Pipeline")
    print("=" * 60)
    print(f"Binary: {binary_path}")
    print(f"FSB files: {', '.join(fsb_files)}")
    print(f"Process: {args.process}")

    found_key = None

    # Phase 1: Static analysis
    keys = static_analysis(binary_path, fsb_files)
    if keys:
        found_key = keys[0]
    else:
        print("\n  -> Static analysis failed. Moving to runtime...")

    # Phase 2: Frida
    if not found_key:
        keys = frida_extract(args.process, fsb_files)
        if keys:
            found_key = keys

    # Phase 3: Remote agent
    if not found_key:
        keys = agent_extract("127.0.0.1", AGENT_PORT, fsb_files, args.process)
        if keys:
            found_key = keys[0]

    # Phase 4: ADB
    if not found_key:
        keys = adb_extract(fsb_files, args.process)
        if keys:
            found_key = keys[0]

    # Phase 5: Fallback
    if not found_key:
        print("\n" + "=" * 60)
        print("[Phase 5] Fallback: Frida Script Generation")
        print("=" * 60)
        generate_frida_script(args.process)
        print("\n[FAILED] All extraction methods exhausted.")
        print("Use the generated Frida script manually.")
        sys.exit(1)

    # Save and decrypt
    save_and_decrypt(found_key, fsb_files, args.output)


def save_and_decrypt(key_hex, fsb_files, output_path=None):
    print("\n" + "=" * 60)
    print(f"*** AES-128 KEY FOUND: {key_hex} ***")
    print("=" * 60)

    if not output_path:
        output_path = os.path.join(NOCTUA_DIR, "aes_key.txt")

    with open(output_path, "w") as f:
        f.write(key_hex + "\n")
    print(f"Key saved to: {output_path}")

    decrypt_and_show(key_hex, fsb_files)


if __name__ == "__main__":
    main()
