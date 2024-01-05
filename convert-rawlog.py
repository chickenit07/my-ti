import json
import sys
import re
import os
import glob
from urllib.parse import urlparse

CHUNK_SIZE = 1024 * 1024

def extract_data_from_line(line):
    url_match = re.search(r'(https?://[^\s:]+)', line)
    if url_match:
        url = url_match.group(1)
        line = line.replace(url, "").strip(":")
        parts = line.split(":")
        if len(parts) == 2:
            username, password = parts
            try:
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
            except ValueError:
                domain = "invalid_ipv6_address"
            
            return {
                "d": domain,
                "u": username,
                "p": password
            }
    return None

def filter_duplicates(data):
    unique_keys = set()
    unique_data = []

    for item in data:
        key = f"{item['d']}-{item['u']}-{item['p']}"
        if key not in unique_keys:
            unique_keys.add(key)
            unique_data.append(item)

    return unique_data

PROGRESS_UPDATE_INTERVAL = 100  # Update progress every 100 lines

def process_file(input_file_path, base_output_directory):
    output_file_path = generate_output_file_path(input_file_path, base_output_directory)
    
    # Check if the output file already exists
    if os.path.exists(output_file_path):
        print(f"Output file {output_file_path} already exists. Skipping processing for {input_file_path}.\n")
        return

    data = []
    line_count = 0
    total_lines = sum(1 for _ in open(input_file_path, 'r', encoding='utf-8'))

    with open(input_file_path, 'r', encoding='utf-8') as infile:
        for line in infile:
            processed_data = extract_data_from_line(line.strip())
            if processed_data:
                data.append(processed_data)
            line_count += 1

            if line_count % PROGRESS_UPDATE_INTERVAL == 0:
                print(f"Convert and remove dumplicate... Completion: {(line_count / total_lines) * 100:.2f}%\n", end='\r')
    
    unique_data = filter_duplicates(data)
    print("Convert and remove duplicate completed.\n")
    print("---------------------------\n")  
    write_to_json(output_file_path, unique_data)

    print(f"Filtered data for {input_file_path} has been saved to {output_file_path}.\n")
    print("====================================================")


def generate_output_file_path(input_file_path, base_output_directory):
    input_directory = os.path.dirname(input_file_path)
    relative_output_directory = os.path.join(base_output_directory, os.path.relpath(input_directory))
    
    if not os.path.exists(relative_output_directory):
        os.makedirs(relative_output_directory)

    output_file_name = os.path.basename(os.path.splitext(input_file_path)[0]) + ".json"
    return os.path.join(relative_output_directory, output_file_name)

def write_to_json(file_path, data):
    total_items = len(data)
    items_written = 0

    with open(file_path, 'w') as outfile:
        for item in data:
            json.dump(item, outfile)
            outfile.write('\n')
            items_written += 1

            progress_percent = (items_written / total_items) * 100
            print(f"Writing to JSON... Completion: {progress_percent:.2f}%", end='\r')

    print("\nWrite to JSON completed.")

if __name__ == "__main__":
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

    if len(sys.argv) != 2:
        print("Usage: python combined_script.py <input_pattern>")
        sys.exit(1)

    input_pattern = sys.argv[1]
    input_files = glob.glob(input_pattern)

    for input_file_path in input_files:
        process_file(input_file_path, "json")