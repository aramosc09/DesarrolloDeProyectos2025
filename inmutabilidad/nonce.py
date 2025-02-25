import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Clase para representar un bloque en la blockchain
class Block:
    def __init__(self, index, previous_hash, document_hash, signature, public_key, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.document_hash = document_hash
        self.signature = signature
        self.public_key = public_key
        self.nonce = nonce  # Nuevo campo para minería
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_content = f"{self.index}{self.previous_hash}{self.document_hash.hex()}{self.signature.hex()}{self.nonce}".encode()
        return hashlib.sha256(block_content).hexdigest()

    def mine_block(self, difficulty):
        prefix = '0' * difficulty  # La dificultad determina cuántos ceros iniciales debe tener el hash
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()

# Clase para gestionar la Blockchain con múltiples nodos
class Blockchain:
    def __init__(self, num_nodos, difficulty=4):
        self.chain = []
        self.nodes = [generate_keys() for _ in range(num_nodos)]  # Claves de validadores
        self.difficulty = difficulty  # Nivel de dificultad para PoW
        self.create_genesis_block()

    def create_genesis_block(self):
        print("\033[94m🟦 Creando Bloque Génesis...\033[0m")
        genesis_hash = hashlib.sha256(b"GENESIS_BLOCK").digest()
        genesis_private, genesis_public = generate_keys()
        genesis_block = Block(0, "0", genesis_hash, b"", genesis_public)
        genesis_block.mine_block(self.difficulty)  # Minar bloque génesis
        self.chain.append(genesis_block)
        print(f"📌 Bloque Génesis minado con hash {genesis_block.hash}")

    def add_block(self, document_hash, signature, public_key):
        print("\033[92m✅ Propuesta de nuevo bloque...\033[0m")
        print(f"🔍 Verificando firma del firmante con clave: {public_key_to_short_pem(public_key)}")

        if not verify_file_signature(public_key, document_hash, signature):
            print("\033[91m❌ Firma inválida con la clave del firmante. Bloque rechazado.\033[0m")
            return

        valid_votes = sum(
            verify_file_signature(public_key, document_hash, signature) for _, pk in self.nodes
        )

        required_votes = len(self.nodes) // 2 + 1
        print(f"🔹 Votos válidos: {valid_votes}/{len(self.nodes)} necesarios: {required_votes}")

        if valid_votes >= required_votes:
            previous_block = self.chain[-1]
            new_block = Block(len(self.chain), previous_block.hash, document_hash, signature, public_key)
            print("⛏️ Minando nuevo bloque...")
            new_block.mine_block(self.difficulty)  # Minar antes de añadirlo
            self.chain.append(new_block)
            print(f"\033[92m📌 Bloque {new_block.index} agregado con hash {new_block.hash}\033[0m")
        else:
            print("\033[91m❌ Bloque rechazado. No se alcanzó consenso.\033[0m")

    def verify_integrity(self):
        print("\033[94m🔍 Verificando integridad de la blockchain...\033[0m")
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i-1].hash:
                print(f"\033[91m❌ Error: Bloque {i} tiene un previous_hash incorrecto.\033[0m")
                return False, i

            print(f"🔍 Verificando firma del bloque {i} con clave: {public_key_to_short_pem(self.chain[i].public_key)}")
            if not verify_file_signature(self.chain[i].public_key, self.chain[i].document_hash, self.chain[i].signature):
                print(f"\033[91m❌ Firma inválida en el bloque {i}.\033[0m")
                return False, i

        print("\033[92m✅ La Blockchain es válida.\033[0m")
        return True, -1
    
    def save_blockchain(self, filename="blockchain.json"):
        print("\033[94m💾 Guardando Blockchain en archivo JSON...\033[0m")
        with open(filename, "w") as f:
            json.dump([{
                "index": block.index,
                "previous_hash": block.previous_hash,
                "nonce": block.nonce,
                "document_hash": block.document_hash.hex(),  # Convertir bytes a hex
                "signature": block.signature.hex(),  # Convertir firma a hex
                "public_keys": public_key_to_pem(block.public_key),  # Claves públicas a PEM
                "hash": block.hash
            } for block in self.chain], f, indent=4)
        print("\033[92m✅ Blockchain guardada exitosamente.\033[0m")

# Funciones de clave y firma

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

def public_key_to_short_pem(public_key):
    pem = public_key_to_pem(public_key)
    return pem.split("\n")[1][:10]

def sign_document(file_data, private_key):
    document_hash = hashlib.sha256(file_data).digest()
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
        print(f"\033[91m❌ Error al verificar firma con clave {public_key_to_short_pem(public_key)}: {e}\033[0m")
        return False

# Simulación de blockchain con PoW
num_nodos = 5
difficulty = 4
blockchain = Blockchain(num_nodos, difficulty)

equipo_1_private, equipo_1_public = generate_keys()
equipo_2_private, equipo_2_public = generate_keys()

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

blockchain.verify_integrity()

blockchain.save_blockchain()
