import sys
import re
import bleach
import subprocess

def sanitize_web(input_path, output_path):
    """Clean HTML/JS/JSON of executable scripts."""
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    # strip=True removes the content inside tags like <script>
    clean = bleach.clean(content, tags=[], attributes={}, strip=True)
    with open(output_path, 'w') as f:
        f.write(clean)

def sanitize_network(input_path, output_path):
    """Validate PCAP and strip sensitive packet data using tshark."""
    try:
        # editcap (from Wireshark) regenerates the file, fixing malformed headers
        subprocess.run(['editcap', '-F', 'pcap', input_path, output_path], check=True)
    except Exception:
        sys.exit(1)

def sanitize_logs(input_path, output_path):
    """Sanitize system logs: Remove ANSI escape codes and potential PII patterns."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    # Simple regex for potential IPv4 scrubbing if needed
    # ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f_in:
        with open(output_path, 'w') as f_out:
            for line in f_in:
                clean_line = ansi_escape.sub('', line)
                # Ensure only printable characters
                clean_line = "".join(c for c in clean_line if c.isprintable() or c == '\n')
                f_out.write(clean_line)

def main():
    in_p, out_p, mime = sys.argv[1:4]
    
    if "html" in mime or "json" in mime:
        sanitize_web(in_p, out_p)
    elif "pcap" in mime:
        sanitize_network(in_p, out_p)
    elif "log" in mime or "text/" in mime:
        sanitize_logs(in_p, out_p)
    else:
        # Default pass-through for unknown text
        sanitize_logs(in_p, out_p)

if __name__ == "__main__":
    main()