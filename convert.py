import json
import re
import os
import glob
import argparse

CHUNK_SIZE = 1024 * 1024  # 1 MB
PROGRESS_UPDATE_INTERVAL = 100  # Update progress every 100 lines

def extract_data_from_line(line):
    # Regular expression pattern to capture the URL
    url_match = re.search(r'(https?://[^\s:]+(:\d+)?(/[^\s]*)*)', line)
    if url_match:
        url = url_match.group(1)
        # Extract username and password from the remaining line after removing the URL
        remaining = line.replace(url, "").strip(":")

        # Check if there's a space after the domain
        #remaining = remaining.replace(" ", "")

        parts = remaining.split(":")
        # Ensure we have exactly two parts (username and password)
        if len(parts) == 2:
            username, password = parts
            
            # Check if username and password are ASCII
            if username.isascii() and password.isascii():
                path_segments = url.split("/")
                domain = path_segments[2] + ("" if url_match.group(2) is None or url_match.group(2) in [":443", ":80"] else url_match.group(2))
                
                # Regular expression pattern to match IP addresses
                ip_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
                
                # If the domain matches the IP address pattern, return None
                if re.match(ip_pattern, domain):
                    return None
                
                # Check the length of domain, username, and password and the count of '=' characters in 'u' and 'p'
                if len(domain) <= 100 and len(username) <= 100 and len(password) <= 100 and (username.count('=') <= 10 and password.count('=') <= 10):
                    return {
                        "d": domain,
                        "u": username,
                        "p": password
                    }
    return None

def process_file(input_file_path, force_remove=False):
    output_file_path = generate_output_file_path(input_file_path)

    if force_remove and os.path.exists(output_file_path):
        os.remove(output_file_path)

    if os.path.exists(output_file_path):
        print(f"Output file {output_file_path} already exists. Skipping processing for {input_file_path}.\n")
        return

    with open(input_file_path, 'r', encoding='utf-8') as infile, open(output_file_path, 'w') as outfile:
        print(f"File {input_file_path} opened for reading.")
        line_count = 0
        total_lines = sum(1 for _ in open(input_file_path, 'r', encoding='utf-8'))
        buffer = ''  # Initialize the buffer variable

        for chunk in iter(lambda: infile.read(CHUNK_SIZE), ''):
            buffer += chunk
            lines = buffer.split('\n')
            
            for line in lines[:-1]:
                # Check if the line contains 'null'; if it does, skip processing this line
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

        # Handle the remaining buffer after the loop
        if buffer:
            # Check if the line contains 'null'; if it does, skip processing this line
            if 'null' not in buffer:
                processed_data = extract_data_from_line(buffer.strip())
                if processed_data:
                    json.dump(processed_data, outfile)
                    outfile.write('\n')

        print(f"Output file {output_file_path} was created.")

        
def generate_output_file_path(input_file_path):
    # Get the directory of the script
    script_directory = os.path.dirname(os.path.abspath(__file__))
    
    # Create a 'json' directory inside the script directory if it doesn't exist
    json_directory = os.path.join(script_directory, "json")
    if not os.path.exists(json_directory):
        os.makedirs(json_directory)

    # Use the 'json' directory as the base output directory
    relative_output_directory = json_directory
    
    # Create the output file path
    output_file_name = os.path.basename(os.path.splitext(input_file_path)[0]) + ".json"
    return os.path.join(relative_output_directory, output_file_name)


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