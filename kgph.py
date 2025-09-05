#!/usr/bin/env python3
# KGPH

def install_pip():
    import subprocess
    import sys
    import os
    import urllib.request
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', '--version'])
        print("PIP is already installed.")
        return
    except subprocess.CalledProcessError:
        print("PIP is not installed. Installing...")
    try:
        subprocess.check_call([sys.executable, '-m', 'ensurepip'])
        print("PIP has been installed successfully using 'ensurepip'.")
        return
    except subprocess.CalledProcessError:
        print("'ensurepip' has failed. Attempting to install PIP via 'get-pip.py'...")
    try:
        url = "https://bootstrap.pypa.io/get-pip.py"
        get_pip_script = "get-pip.py"
        urllib.request.urlretrieve(url, get_pip_script)
        print("Downloaded 'get-pip.py'.")
        subprocess.check_call([sys.executable, get_pip_script])
        print("PIP has been installed successfully using 'get-pip.py'.")
        os.remove(get_pip_script)
        print("Cleaned up 'get-pip.py'.")
    except Exception as e:
        print(f"Failed to install PIP: {e}")
        sys.exit(1)

def pip_install(package_name, upgrade=True, user=False):
    import subprocess
    import sys
    def install_package(package_name):
        try:
            command = [sys.executable, '-m', 'pip', 'install', package_name]
            if upgrade:
                command.append('--upgrade')
            if user:
                command.append('--user')
            subprocess.run(command, check=True)
            print(f"{package_name} has been installed successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package_name}: {e}")
    install_package(package_name)

def upgrade_pip():
    import subprocess
    import sys
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        print("PIP has been upgraded successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to upgrade PIP: {e}")

def clear_screen():
    import os
    size = os.get_terminal_size()
    rows = size.lines
    print("\n")
    print("\n" * rows, end="")

try:
    import os
    import base64
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import tarfile
    from pathlib import Path
    import urllib.request
    from github import Github
    import getpass
    import argparse
except Exception as e:
    install_pip()
    upgrade_pip()
    pip_install("cryptography")
    pip_install("PyGithub")
    import os
    import sys
    os.execv(sys.executable, [sys.executable] + sys.argv)

def encrypt_message(message: str, knexyce_key: str, iterations=1200000):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_data = salt + iv + tag + encrypted_message
    encrypted_message = base64.b64encode(encrypted_data).decode()
    return encrypted_message

def decrypt_message(encrypted_message: str, knexyce_key: str, iterations=1200000):
    encrypted_data = base64.b64decode(encrypted_message)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    encrypted_message = encrypted_data[44:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(knexyce_key.encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

def encrypt_file(input_file: str, output_file: str, knexyce_key: str):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        encrypted_data = encrypt_message(base64.b64encode(data).decode(), knexyce_key)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error: {e}")

def decrypt_file(input_file: str, output_file: str, knexyce_key: str):
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            encrypted_data = f.read()
        decrypted_base64 = decrypt_message(encrypted_data, knexyce_key)
        decrypted_data = base64.b64decode(decrypted_base64)
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
    except Exception as e:
        print(f"Error: {e}")

def archive_folder(source_folder: str, output_archive: str):
    source_path = Path(source_folder)
    with tarfile.open(output_archive, "w:gz") as tar:
        for item in source_path.iterdir():
            tar.add(item, arcname=item.name)

def extract_archive(archive_file: str, output_folder: str):
    extract_path = Path(output_folder)
    extract_path.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_file, "r:gz") as tar:
        tar.extractall(path=extract_path)

def download_file(url, save_path):
    with urllib.request.urlopen(url) as response:
        file_data = response.read()
    with open(save_path, 'wb') as f:
        f.write(file_data)

def get_github_file(author, source, branch, target_file):
    download_file(f"https://raw.githubusercontent.com/{author}/{source}/{branch}/{target_file}", target_file)

def upload_to_github(token, repo_name, file_path, commit_message="Uploaded text file."):
    g = Github(token)
    user = g.get_user()
    try:
        repo = user.get_repo(repo_name)
    except:
        repo = user.create_repo(repo_name, private=False)
    file_name = os.path.basename(file_path)
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    try:
        existing_file = repo.get_contents(file_name)
        repo.update_file(existing_file.path, commit_message, content, existing_file.sha)
    except:
        repo.create_file(file_name, commit_message, content)

def delete_github_repo(token, repo_name):
    g = Github(token)
    user = g.get_user()
    try:
        repo = user.get_repo(repo_name)
        repo.delete()
    except Exception as e:
        print(f"Error: {e}.")

def mkpkg(package_folder, enc_key=None, token=None):
    if enc_key == None:
       enc_key = getpass.getpass(f"Enter a passphrase to encrypt '{package_folder}'. ")
    if token == None:
        token = getpass.getpass("Enter a Repository scope GitHub PAT. ")
    package_archive = f"{package_folder}.tar.gz"
    archive_folder(package_folder, package_archive)
    package_enc = f"{package_folder}.enc"
    encrypt_file(package_archive, package_enc, enc_key)
    upload_to_github(token, package_folder, package_enc)
    os.remove(package_enc)
    os.remove(package_archive)

def getpkg(author, package_name, enc_key=None, package_location=None):
    if enc_key == None:
       enc_key = getpass.getpass(f"Enter a passphrase to encrypt '{package_name}'. ")
    if package_location is None:
        package_location = package_name
    package_enc = f"{package_name}.enc"
    get_github_file(author, package_name, "main", package_enc)
    package_archive = f"{package_name}.tar.gz"
    decrypt_file(package_enc, package_archive, enc_key)
    extract_archive(package_archive, package_location)
    os.remove(package_enc)
    os.remove(package_archive)

def rmpkg(package_name, token=None):
    if token == None:
        token = getpass.getpass("Enter a Repository deletion scope GitHub PAT. ")
    delete_github_repo(token, package_name)

def main():
    parser = argparse.ArgumentParser(
        description="KGPH (Knexyce GitHub Package Handler) is a tool to handle encrypted packages."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    parser_getpkg = subparsers.add_parser("getpkg", help="Download and decrypt a package from GitHub.")
    parser_getpkg.add_argument("-a", "--author", required=True, help="Package author.")
    parser_getpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_getpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_getpkg.add_argument("-l", "--location", help="Download path.", default=None)
    parser_mkpkg = subparsers.add_parser("mkpkg", help="Encrypt and upload a package to GitHub.")
    parser_mkpkg.add_argument("-f", "--folder", required=True, help="Package folder.")
    parser_mkpkg.add_argument("-k", "--key", help="Encryption key.")
    parser_mkpkg.add_argument("-t", "--token", help="GitHub personal access token.", default=None)
    parser_rmpkg = subparsers.add_parser("rmpkg", help="Delete a package from GitHub.")
    parser_rmpkg.add_argument("-p", "--package", required=True, help="Package name.")
    parser_rmpkg.add_argument("-t", "--token", help="GitHub personal access token.", default=None)
    args = parser.parse_args()
    if args.command == "getpkg":
        getpkg(args.author, args.package, args.key, args.location)
    elif args.command == "mkpkg":
        mkpkg(args.folder, args.key, args.token)
    elif args.command == "rmpkg":
        rmpkg(args.package, args.token)

if __name__ == "__main__":
    main()

# Author Ayan Alam (Knexyce).
# Note: Knexyce is both a group and individual.
# All rights regarding this software are reserved by Knexyce only.