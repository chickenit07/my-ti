import json
import re
import os
import glob
import argparse
import chardet

CHUNK_SIZE = 1024 * 1024  # 1 MB
PROGRESS_UPDATE_INTERVAL = 100  # Update progress every 100 lines

def detect_encoding(file_path):
    """Detect file encoding to avoid UnicodeDecodeError."""
    with open(file_path, 'rb') as f:
        raw_data = f.read(10000)  # Read first 10 KB for detection
    result = chardet.detect(raw_data)
    return result['encoding'] if result['encoding'] else 'latin-1'  # Default to 'latin-1' if detection fails

def extract_data_from_line(line):
    """Extracts domain, username, and password from a line."""
    url_match = re.search(r'(https?://[^\s:]+(:\d+)?(/[^\s]*)*)', line)
    if url_match:
        url = url_match.group(1)
        remaining = line.replace(url, "").strip(":")
        parts = remaining.split(":")
        
        if len(parts) == 2:
            username, password = parts
            
            if username.isascii() and password.isascii():
                path_segments = url.split("/")
                domain = path_segments[2] + ("" if url_match.group(2) in [None, ":443", ":80"] else url_match.group(2))
                
                ip_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
                
                if re.match(ip_pattern, domain):
                    return None
                
                if len(domain) <= 100 and len(username) <= 100 and len(password) <= 100 and (username.count('=') <= 10 and password.count('=') <= 10):
                    return {
                        "d": domain,
                        "u": username,
                        "p": password
                    }
    return None

def process_file(input_file_path, force_remove=False):
    """Processes the input file and extracts credentials to a JSON file."""
    output_file_path = generate_output_file_path(input_file_path)

    if force_remove and os.path.exists(output_file_path):
        os.remove(output_file_path)

    if os.path.exists(output_file_path):
        print(f"Output file {output_file_path} already exists. Skipping {input_file_path}.\n")
        return

    encoding = detect_encoding(input_file_path)  # Detect encoding
    print(f"Detected Encoding for {input_file_path}: {encoding}")

    try:
        with open(input_file_path, 'r', encoding=encoding, errors='ignore') as infile, open(output_file_path, 'w') as outfile:
            print(f"Processing {input_file_path}...")

            line_count = 0
            total_lines = sum(1 for _ in open(input_file_path, 'r', encoding=encoding, errors='ignore'))
            buffer = ""

            for chunk in iter(lambda: infile.read(CHUNK_SIZE), ''):
                buffer += chunk
                lines = buffer.split('\n')

                for line in lines[:-1]:
                    if 'null' in line:
                        continue
                    
                    processed_data = extract_data_from_line(line.strip())
                    if processed_data:
                        json.dump(processed_data, outfile)
                        outfile.write('\n')

                    line_count += 1
                    if line_count % PROGRESS_UPDATE_INTERVAL == 0:
                        progress_percent = (line_count / total_lines) * 100
                        print(f"Converting... Completion: {progress_percent:.2f}%", end='\r')

                buffer = lines[-1]

            if buffer and 'null' not in buffer:
                processed_data = extract_data_from_line(buffer.strip())
                if processed_data:
                    json.dump(processed_data, outfile)
                    outfile.write('\n')

        print(f"\nOutput file created: {output_file_path}")

    except Exception as e:
        print(f"Error processing {input_file_path}: {e}")

def generate_output_file_path(input_file_path):
    """Generates output file path in 'json' directory."""
    script_directory = os.path.dirname(os.path.abspath(__file__))
    json_directory = os.path.join(script_directory, "json")
    os.makedirs(json_directory, exist_ok=True)

    output_file_name = os.path.basename(os.path.splitext(input_file_path)[0]) + ".json"
    return os.path.join(json_directory, output_file_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process input files.')
    parser.add_argument('input_pattern', type=str, help='Input file pattern')
    parser.add_argument('-f', '--force', action='store_true', help='Force remove existing output files')

    print("""
                 / \\__
                (    @\\___
                 /         O
                /   (_____/
                /_____/ U
            Magic trash removal
             -----------------
    Don't let anyone know your next move
====================================================
    """)
    print("Starting...\n")
    print("====================================================")
    
    args = parser.parse_args()
    input_files = glob.glob(args.input_pattern)

    for input_file_path in input_files:
        process_file(input_file_path, force_remove=args.force)
