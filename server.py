from flask import Flask, request, jsonify, render_template
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import os
from pathlib import Path
import logging
import jwt
import qrcode
import io
import base64
import hashlib
import datetime
import uuid
import fitz # PyMuPDF pour le tamponnage PDF

app = Flask(__name__)

# --- BASES DE DONNÉES (MÉMOIRE) ---
users_db = {}         # Clés PRIVÉES (Cryptées) - Pour signer
public_keys_db = {}   # Clés PUBLIQUES (Annuaire) - Pour vérifier automatiquement
revocation_list = set() # Liste Noire (CRL)

# --- SÉCURITÉ SERVEUR ---
KEY_FILE = Path(__file__).parent / "server_master.key"
if KEY_FILE.exists():
    SERVER_MASTER_KEY = KEY_FILE.read_bytes()
else:
    SERVER_MASTER_KEY = Fernet.generate_key()
    KEY_FILE.write_bytes(SERVER_MASTER_KEY)

cipher_suite = Fernet(SERVER_MASTER_KEY)

@app.route('/')
def home():
    template_path = Path(__file__).parent / "templates" / "index.html"
    if template_path.exists(): return render_template('index.html')
    return "<h1>Erreur: Template manquant</h1>"

# ---------------------------------------------------------
# ROUTE 1 : INSCRIPTION
# ---------------------------------------------------------
@app.route('/api/register', methods=['POST'])
def register():
    user_id = request.json.get('username')
    # Si l'utilisateur était banni, on le réinitialise s'il recrée une clé
    if user_id in revocation_list: revocation_list.remove(user_id)
    
    # Génération RSA 2048 bits
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 1. Sauvegarde Privée (Cachée et Chiffrée)
    pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    users_db[user_id] = cipher_suite.encrypt(pem_private)
    
    # 2. Sauvegarde Publique (Dans l'Annuaire pour auto-vérification)
    pem_public = private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_keys_db[user_id] = pem_public.decode('utf-8') 

    return jsonify({
        "message": "Identité Active & Annuaire mis à jour", 
        "public_key": pem_public.decode('utf-8')
    })

# ---------------------------------------------------------
# ROUTE 2 : SIGNATURE & TAMPONNAGE
# ---------------------------------------------------------
@app.route('/api/sign', methods=['POST'])
def sign_file():
    user_id = request.form.get('username')
    uploaded_file = request.files['file']
    file_data = uploaded_file.read()

    # Vérifications de sécurité
    if user_id not in users_db: return jsonify({"error": "Utilisateur inconnu"}), 404
    if user_id in revocation_list: return jsonify({"error": "REFUSÉ : Certificat Révoqué (Volé)"}), 403

    try:
        pem_private = cipher_suite.decrypt(users_db[user_id])
        private_key = serialization.load_pem_private_key(pem_private, password=None)
    except: return jsonify({"error": "Erreur interne"}), 500

    # Création du Token JWT
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "name": user_id, 
        "Timestamp UNIX": now.timestamp(), 
        "ID": str(uuid.uuid4()),
        "date": now.strftime("%Y-%m-%d %H:%M:%S UTC"), 
        "hash": hashlib.sha256(file_data).hexdigest(),
        "filename": uploaded_file.filename, 
        "type": "doc_sign", 
        "certification": "Signé par Signex ©"
    }
    encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

    # Génération QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(encoded_jwt)
    qr.make(fit=True)
    img_qr = qr.make_image(fill='black', back_color='white')
    
    # Tamponnage PDF (Watermarking)
    pdf_base64 = ""
    if uploaded_file.filename.lower().endswith('.pdf'):
        try:
            qr_byte_stream = io.BytesIO()
            img_qr.save(qr_byte_stream, format="PNG")
            doc = fitz.open(stream=file_data, filetype="pdf")
            page = doc[-1] # Dernière page
            # Position: En bas à droite
            rect = fitz.Rect(page.rect.width - 100, page.rect.height - 100, page.rect.width - 10, page.rect.height - 10)
            page.insert_image(rect, stream=qr_byte_stream.getvalue())
            pdf_buffer = io.BytesIO()
            doc.save(pdf_buffer)
            doc.close()
            pdf_base64 = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
        except Exception as e: 
            print(f"Erreur PDF: {e}")

    # Image pour affichage web
    img_display = io.BytesIO()
    img_qr.save(img_display, format="PNG")
    img_str = base64.b64encode(img_display.getvalue()).decode('utf-8')

    return jsonify({
        "filename": uploaded_file.filename, 
        "jwt_token": encoded_jwt, 
        "qr_image": img_str, 
        "signed_pdf": pdf_base64
    })

# ---------------------------------------------------------
# ROUTE 3 : VÉRIFICATION INTELLIGENTE (AUTO-KEY)
# ---------------------------------------------------------
@app.route('/api/verify', methods=['POST'])
def verify_signature():
    uploaded_file = request.files.get('file') 
    jwt_token = request.form.get('jwt_token') 
    public_key_pem = request.form.get('public_key') 

    if not jwt_token: return jsonify({"valid": False, "message": "Token manquant"})

    # --- LOGIQUE 1 : RÉCUPÉRATION AUTOMATIQUE DE LA CLÉ ---
    # Si le client (Mobile) n'a pas la clé, on la cherche dans l'annuaire
    if not public_key_pem:
        try:
            # On décode sans vérifier la signature juste pour lire le nom
            unverified = jwt.decode(jwt_token, options={"verify_signature": False})
            signer_name = unverified.get('name')
            
            if signer_name in public_keys_db:
                public_key_pem = public_keys_db[signer_name]
            else:
                return jsonify({"valid": False, "message": f"Clé introuvable pour {signer_name}. Veuillez utiliser un ordinateur."})
        except:
             return jsonify({"valid": False, "message": "Token illisible."})

    # --- LOGIQUE 2 : VÉRIFICATION CRYPTOGRAPHIQUE ---
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        decoded_payload = jwt.decode(jwt_token, public_key, algorithms=["RS256"], options={"verify_iat": False})
        signer_name = decoded_payload.get('name')
        
        # Check CRL (Révocation)
        if signer_name in revocation_list:
             return jsonify({"valid": False, "mode": "revoked", "message": f"⛔ ALERTE : Le certificat de {signer_name} a été déclaré VOLÉ !"})

        # --- MODE A : AUDIT COMPLET (Fichier présent) ---
        if uploaded_file:
            current_hash = hashlib.sha256(uploaded_file.read()).hexdigest()
            if decoded_payload.get('hash') == current_hash:
                msg = (f"✅ <b>DOCUMENT INTÈGRE & AUTHENTIQUE</b><br>"
                       f"Signé par : <b>{signer_name}</b><br>"
                       f"Date : {decoded_payload.get('date')}")
                return jsonify({"valid": True, "mode": "full", "message": msg})
            else:
                return jsonify({"valid": False, "mode": "error", "message": "❌ ALERTE : La signature est bonne, mais le contenu du fichier a été MODIFIÉ !"})
        
        # --- MODE B : SCAN RAPIDE (Pas de fichier) ---
        else:
            msg = (f"⚠️ <b>IDENTITÉ VALIDÉE (Scan Rapide)</b><br>"
                   f"Signataire : <b>{signer_name}</b><br>"
                   f"Date : {decoded_payload.get('date')}<br>"
                   f"<i class='text-xs opacity-70'>Fichier non vérifié (Clé récupérée de l'annuaire).</i>")
            return jsonify({"valid": True, "mode": "partial", "message": msg})

    except Exception as e: return jsonify({"valid": False, "message": f"Erreur: {str(e)}"})

# ROUTE RÉVOCATION
@app.route('/api/revoke', methods=['POST'])
def revoke_key():
    user = request.json.get('username')
    revocation_list.add(user)
    return jsonify({"message": f"Clé de {user} révoquée."})

if __name__ == '__main__':
    # Écoute sur toutes les interfaces pour que ngrok/mobile fonctionne
    app.run(host='0.0.0.0', debug=True, port=5001)