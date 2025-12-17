from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class SystemeDeSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    # 1. GÉNÉRATION DES CLÉS (Ce que ton serveur fera à l'inscription)
    def generer_cles(self):
        print("\n--- 1. Génération des clés ---")
        # On crée la clé privée (Celle que le serveur garde secrète)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # On extrait la clé publique (Celle que l'utilisateur reçoit)
        self.public_key = self.private_key.public_key()
        print("✅ Clés générées : Privée (Cachée) et Publique (Partageable)")

    # 2. SIGNATURE (Ce que fait le serveur quand on upload un fichier)
    def signer_document(self, message):
        print(f"\n--- 2. Signature du document : '{message}' ---")
        
        # Conversion du message en bytes (binaire)
        message_bytes = message.encode('utf-8')

        # Création de la signature
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # Ici on utilise le Hachage SHA-256
        )
        print(f"✅ Document signé ! La signature numérique ressemble à : {signature.hex()[:50]}...")
        return signature

    # 3. VÉRIFICATION (Ce que fait n'importe qui avec la clé publique)
    def verifier_document(self, message, signature):
        print(f"\n--- 3. Tentative de vérification pour : '{message}' ---")
        message_bytes = message.encode('utf-8')
        
        try:
            self.public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("🟢 SUCCÈS : Le document est authentique et n'a pas été modifié.")
            return True
        except Exception as e:
            print("🔴 ALERTE : Échec de la vérification ! Document modifié ou fausse signature.")
            return False

# ==========================================
# SCÉNARIO DE TEST (DEMO)
# ==========================================

# Initialisation du système
app = SystemeDeSignature()
app.generer_cles()

# Scénario A : Tout se passe bien
mon_document_original = "Contrat : Je dois 1000 euros à Achraf."
ma_signature = app.signer_document(mon_document_original)

# Vérification du document original
app.verifier_document(mon_document_original, ma_signature)

# ------------------------------------------

# Scénario B : L'Attaque (Hacker)
print("\n... 🕵️  Un hacker intercepte le document et change le montant ...")

document_pirate = "Contrat : Je dois 9000000 euros à Achraf." 
# Note : Le hacker a le document et la signature, mais PAS la clé privée pour refaire la signature.

# On essaie de vérifier le document piraté avec la signature originale
app.verifier_document(document_pirate, ma_signature)