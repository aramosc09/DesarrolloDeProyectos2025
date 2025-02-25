import hashlib
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
        block_content = f"{self.index}{self.previous_hash}{self.document_hash.hex()}{self.signature.hex()}".encode()
        return hashlib.sha256(block_content).hexdigest()

# Clase para gestionar la Blockchain con múltiples nodos
class Blockchain:
    def __init__(self, num_nodos):
        self.chain = []
        self.nodes = [generate_keys() for _ in range(num_nodos)]  # Lista de pares de claves para nodos
        self.create_genesis_block()

    def create_genesis_block(self):
        print("\033[94m🟦 Creando Bloque Génesis...\033[0m")
        genesis_hash = hashlib.sha256(b"GENESIS_BLOCK").digest()  # Hash en bytes
        genesis_block = Block(0, "0", genesis_hash, b"", [])  # Firma vacía en bytes
        self.chain.append(genesis_block)

    def add_block(self, document_hash, signature, public_key):
        print("\033[92m✅ Agregando nuevo bloque...\033[0m")
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), previous_block.hash, document_hash, signature, [public_key])
        self.chain.append(new_block)
        print(f"📌 Bloque {new_block.index} agregado con hash {new_block.hash}")

    def verify_integrity(self):
        print("\033[94m🔍 Verificando integridad de la blockchain...\033[0m")
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i-1].hash:
                print(f"\033[91m❌ Error en integridad: Bloque {i} tiene un previous_hash incorrecto.\033[0m")
                return False, i

            public_key = self.chain[i].public_keys[0]
            valid_signature = verify_file_signature(public_key, self.chain[i].document_hash, self.chain[i].signature)

            if not valid_signature:
                print(f"\033[91m❌ Error: Firma inválida en el bloque {i}.\033[0m")
                return False, i

        print("\033[92m✅ La Blockchain es válida.\033[0m")
        return True, -1

    def save_blockchain(self, filename="blockchain.json"):
        print("\033[94m💾 Guardando Blockchain en archivo JSON...\033[0m")
        with open(filename, "w") as f:
            json.dump([{
                "index": block.index,
                "previous_hash": block.previous_hash,
                "document_hash": block.document_hash.hex(),  # Convertir bytes a hex
                "signature": block.signature.hex(),  # Convertir firma a hex
                "public_keys": [public_key_to_pem(pk) for pk in block.public_keys],  # Claves públicas a PEM
                "hash": block.hash
            } for block in self.chain], f, indent=4)
        print("\033[92m✅ Blockchain guardada exitosamente.\033[0m")

# Función para generar claves de cada nodo
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def public_key_to_pem(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

# Función para firmar un documento
def sign_document(file_data, private_key):
    document_hash = hashlib.sha256(file_data).digest()  # Hash en bytes
    signature = private_key.sign(
        document_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"\033[92m🔏 Documento firmado. Hash: {document_hash.hex()}\033[0m")
    return document_hash, signature

# Función para verificar la firma
def verify_file_signature(public_key, document_hash, signature):
    try:
        public_key.verify(
            signature,
            document_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"\033[91m❌ Error al verificar firma: {e}\033[0m")
        return False

# Simulación de blockchain con múltiples nodos
num_nodos = 5
blockchain = Blockchain(num_nodos)

# Generar claves para dos equipos
equipo_1_private, equipo_1_public = generate_keys()
equipo_2_private, equipo_2_public = generate_keys()

# Simulación de firmas con documentos válidos
document_path = "gOd.png"
with open(document_path, "rb") as f:
    file_data = f.read()
document_hash_1, signature_1 = sign_document(file_data, equipo_1_private)
blockchain.add_block(document_hash_1, signature_1, equipo_1_public)

document_path_modified = "gOd copy.png"
with open(document_path_modified, "rb") as f:
    file_data_modified = f.read()
document_hash_2, signature_2 = sign_document(file_data_modified, equipo_2_private)
blockchain.add_block(document_hash_2, signature_2, equipo_2_public)

print(f"\n📜 Hash del documento original: {document_hash_1.hex()}")
print(f"📜 Hash del documento modificado: {document_hash_2.hex()}")

# Verificación de integridad
tampered, block_index = blockchain.verify_integrity()
if not tampered:
    print(f"\033[91m🔴 Se detectó una alteración en el bloque {block_index}.\033[0m")

blockchain.save_blockchain()