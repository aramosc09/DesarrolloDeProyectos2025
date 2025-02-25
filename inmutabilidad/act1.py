import hashlib
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Clase para representar un bloque en la blockchain
class Block:
    def __init__(self, index, previous_hash, document_hash, signature, public_keys):
        self.index = index
        self.previous_hash = previous_hash
        self.document_hash = document_hash
        self.signature = signature
        self.public_keys = public_keys  # Lista de claves públicas de los nodos validadores
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_content = f"{self.index}{self.previous_hash}{self.document_hash}{self.signature}".encode()
        return hashlib.sha256(block_content).hexdigest()

# Clase para gestionar la Blockchain con múltiples nodos
class Blockchain:
    def __init__(self, num_nodos):
        self.chain = []
        self.nodes = [generate_keys() for _ in range(num_nodos)]  # Lista de pares de claves para nodos
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(0, "0", "GENESIS_HASH", "", [])
        self.chain.append(genesis_block)

    def add_block(self, document_hash, signature, public_key):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, document_hash, signature, [public_key])
        self.chain.append(new_block)

    def verify_integrity(self):
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i-1].hash:
                return False, i
            if not self.validate_block(self.chain[i]):
                return False, i
        return True, -1

    def validate_block(self, block):
        # Verifica si al menos la mitad de los nodos validan el bloque basándose en el hash del documento
        return any(
            block.document_hash == prev_block.document_hash for prev_block in self.chain
        )

# Función para generar claves de cada nodo
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Función para firmar un documento
def sign_document(private_key, document_path):
    with open(document_path, "rb") as f:
        document_content = f.read()
    document_hash = hashlib.sha256(document_content).hexdigest()
    signature = private_key.sign(
        document_hash.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),  # <-- Volvemos a PSS
        hashes.SHA256()
    )
    return document_hash, signature

# Función para verificar la firma
def verify_signature(public_key, document_hash, signature):
    try:
        public_key.verify(
            signature,
            document_hash.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Simulación de blockchain con múltiples nodos
num_nodos = 5  # Número de nodos validadores
blockchain = Blockchain(num_nodos)

# Generar claves para dos equipos
equipo_1_private, equipo_1_public = generate_keys()
equipo_2_private, equipo_2_public = generate_keys()

# Simulación de firmas con documentos válidos e inválidos
document_path = "gOd.png"
document_hash_1, signature_1 = sign_document(equipo_1_private, document_path)
blockchain.add_block(document_hash_1, signature_1, equipo_1_public)

document_path_modified = "gOd.png"
document_hash_2, signature_2 = sign_document(equipo_2_private, document_path_modified)
blockchain.add_block(document_hash_2, signature_2, equipo_2_public)

# Verificación de integridad
tampered, block_index = blockchain.verify_integrity()
if tampered:
    print("La Blockchain es válida.")
else:
    print(f"Se detectó una alteración en el bloque {block_index}.")
