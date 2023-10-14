import re
import os

def replace_md_links(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Regular expression to find markdown links
    md_link_regex = re.compile(r'\[(.*?)\]\((https://www\.elastic\.co/guide/en/(.*?))\)')

    # Replace markdown links with asciidoc format
    new_content = md_link_regex.sub(r'{security-guide}/\3[\1]', content)

    # Write the modified content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(new_content)

def main():
    # Directory where .asciidoc files are stored
    root_dir = '/Users/tdejesus/code/src/security-docs/docs/detections'

    # Walk through the directory
    for foldername, subfolders, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.endswith('.asciidoc'):
                replace_md_links(os.path.join(foldername, filename))

if __name__ == "__main__":
    main()
