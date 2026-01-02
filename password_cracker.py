#Hasil setelah konfigurasi password_cracker.py

import hashlib

def crack_sha1_hash(sha1_hash, use_salts=False):
    """
    Cracks a SHA-1 hash by comparing it against a list of known passwords and optionally salts.
    
    Args:
        sha1_hash (str): The SHA-1 hash to crack
        use_salts (bool): If True, attempts to crack using passwords + salts combination
    
    Returns:
        str: The original password if found, or "PASSWORD NOT IN DATABASE"
    
    Logic:
        1. Read passwords dari file top-10000-passwords.txt
        2. Jika use_salts=False:
            - Untuk setiap password, hash dengan SHA-1
            - Bandingkan dengan input hash
            - Jika match, return password
        3. Jika use_salts=True:
            - Baca salts dari file known-salts.txt
            - Untuk setiap password dan salt:
              - Gabungkan: salt + password
              - Hash dengan SHA-1
              - Bandingkan dengan input hash
              - Jika match, return password
        4. Jika tidak ada match, return "PASSWORD NOT IN DATABASE"
    """
    
    # Baca daftar password dari file
    try:
        with open('top-10000-passwords.txt', 'r') as f:
            passwords = f.read().split()
    except FileNotFoundError:
        return "PASSWORD NOT IN DATABASE"
    
    # Coba setiap password
    for password in passwords:
        # BAGIAN 1: Coba tanpa salt (hash langsung)
        if hashlib.sha1(password.encode()).hexdigest() == sha1_hash:
            return password
        
        # BAGIAN 2: Jika use_salts=True, baca dan coba dengan salt
        if use_salts:
            try:
                with open('known-salts.txt', 'r') as f:
                    salts = f.read().split()
            except FileNotFoundError:
                pass
            else:
                for salt in salts:
                    # Coba: salt + password
                    salted = salt + password
                    if hashlib.sha1(salted.encode()).hexdigest() == sha1_hash:
                        return password
                    
                    # Coba: password + salt
                    salted = password + salt
                    if hashlib.sha1(salted.encode()).hexdigest() == sha1_hash:
                        return password
    
    # Jika tidak ada match setelah semua kombinasi dicoba
    return "PASSWORD NOT IN DATABASE"