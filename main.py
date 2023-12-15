import os
import magic
import pywt
from entropy import shannon_entropy
import winreg

def analyze_file_entropy(file_path):
    with open(file_path, "rb") as file:
        file_content = file.read()
        entropy = shannon_entropy(file_content)
        print(f"Энтропия файла {file_path}: {entropy}")
        return entropy

def static_wavelet_analysis(file_path):
    with open(file_path, "rb") as file:
        file_content = file.read()
        print(f"Статический вейвлет-анализ файла {file_path}")

def search_crypto_registry_entries():
    print()

def collect_encrypted_files(directory_path):
    magic_obj = magic.Magic()
    encrypted_files = {}
    
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_signature = magic_obj.from_file(file_path)
            print(f"Файл: {file_path}, Сигнатура: {file_signature}")
            if "ZIP" in file_signature.upper() or "GPG" in file_signature.upper() or "PGP" in file_signature.upper() or \
                    "PKCS7" in file_signature.upper() or "ASN.1" in file_signature.upper() or \
                    "PGP" in file_signature.upper() or "OPENPGP" in file_signature.upper() or \
                    "RAR" in file_signature.upper() or "7Z" in file_signature.upper() or \
                    "TAR" in file_signature.upper() or "XZ" in file_signature.upper() or \
                    "GZIP" in file_signature.upper():
                with open(file_path, "rb") as file:
                    file_content = file.read()
                    encrypted_files[file_name] = file_content
                    print(f"Найден файл с распознанной сигнатурой контейнера!")
                    entropy_result = analyze_file_entropy(file_path)
                    if entropy_result > 0:
                        static_wavelet_analysis(file_path)
                        search_crypto_registry_entries()
            else:
                entropy_result = analyze_file_entropy(file_path)
                if entropy_result > 0:
                    static_wavelet_analysis(file_path)
                    search_crypto_registry_entries()
    
    return encrypted_files

if __name__ == "__main__":
    print("Введите директорию для поиска:")
    directory_to_check = input()
    encrypted_files_dict = collect_encrypted_files(directory_to_check)
    for file_name, file_content in encrypted_files_dict.items():
        print(f"Имя файла: {file_name}, Содержимое: {file_content}")
