import sys
from scapy.all import rdpcap, Raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PCAP_FILE = "transacciones_cifradas.pcap"
KEY_FILE = "clave_privada.pem"

print(f"[*] Cargando clave privada: {KEY_FILE}")
with open(KEY_FILE, "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

rsa_bytes_len = private_key.key_size // 8
print(f"[+] Clave RSA: {private_key.key_size} bits (bloque cifrado = {rsa_bytes_len} bytes)")

print(f"[*] Analizando captura de red: {PCAP_FILE}")
paquetes = rdpcap(PCAP_FILE)

# 1. Procesar el Paquete 1 (RSA PIN)
pkt1_data = bytes(paquetes[0][Raw].load)

# Eliminar etiqueta 'RSA PIN|' o similar si existe al inicio
if b"|" in pkt1_data[:15]:
    datos_pin = pkt1_data.split(b"|", 1)[1]
else:
    datos_pin = pkt1_data

salt = datos_pin[:16]
bloque_rsa = datos_pin[16:16 + rsa_bytes_len]

print("\n" + "="*55)
print("1. RECUPERACIÓN DEL PIN (RSA-OAEP SHA-256)")
print("="*55)

try:
    pin_bytes = private_key.decrypt(
        bloque_rsa,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    pin_str = pin_bytes.decode('utf-8', errors='ignore').strip()
    print(f"[+] PIN recuperado: {pin_str}")
    print(f"[+] Salt extraída (16 bytes hex): {salt.hex()}")
except Exception as e:
    print(f"[-] Error al descifrar el bloque RSA: {e}")
    sys.exit(1)

# 2. Derivación de la clave AES-256 con Scrypt
print("\n" + "="*55)
print("2. DERIVACIÓN DE CLAVE AES (SCRYPT)")
print("="*55)

kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1
)
clave_aes = kdf.derive(pin_str.encode('utf-8'))
print(f"[+] Clave AES-256 derivada (hex): {clave_aes.hex()}")

# 3. Descifrado de transacciones AES-GCM (Paquetes 2 en adelante)
print("\n" + "="*70)
print(f"{'3. TRANSACCIONES FINANCIERAS RECUPERADAS (AES-GCM)':^70}")
print("="*70)

aesgcm = AESGCM(clave_aes)
exitos = 0

for i, pkt in enumerate(paquetes[1:], start=2):
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)
        
        # Remover cabecera 'AESGCM|' si existe
        if b"|" in payload[:15]:
            datos_cifrados = payload.split(b"|", 1)[1]
        else:
            datos_cifrados = payload
            
        if len(datos_cifrados) < 28:
            continue
            
        nonce = datos_cifrados[:12]
        ciphertext = datos_cifrados[12:]
        
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            mensaje = plaintext.decode('utf-8', errors='ignore').strip()
            print(f"[Paquete #{i:02d}] {mensaje}")
            exitos += 1
        except Exception:
            pass

# Si no hubo descifrados, intentar derivando con pin_bytes crudo
if exitos == 0:
    kdf_fallback = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    clave_aes_alt = kdf_fallback.derive(pin_bytes)
    aesgcm_alt = AESGCM(clave_aes_alt)
    for i, pkt in enumerate(paquetes[1:], start=2):
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            datos_cifrados = payload.split(b"|", 1)[1] if b"|" in payload[:15] else payload
            if len(datos_cifrados) < 28:
                continue
            nonce = datos_cifrados[:12]
            ciphertext = datos_cifrados[12:]
            try:
                plaintext = aesgcm_alt.decrypt(nonce, ciphertext, None)
                mensaje = plaintext.decode('utf-8', errors='ignore').strip()
                print(f"[Paquete #{i:02d}] {mensaje}")
                exitos += 1
            except Exception:
                pass

print("="*70)
print(f"[+] Total de transacciones descifradas con éxito: {exitos}")
