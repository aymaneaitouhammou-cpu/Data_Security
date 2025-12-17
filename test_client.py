import requests

BASE_URL = "http://127.0.0.1:5000/api"

# 1. Inscription
print("--- 1. Inscription ---")
response = requests.post(f"{BASE_URL}/register", json={"username": "achraf"})
data = response.json()
print("Réponse serveur:", data['message'])
ma_cle_publique = data['public_key'] # L'utilisateur garde sa clé publique
print("Clé publique reçue.")

# 2. Création d'un fichier test
with open("contrat.txt", "w") as f:
    f.write("Je soussigne, devoir 1000 euros.")

# 3. Demande de signature au serveur
print("\n--- 2. Envoi du fichier pour signature ---")
files = {'file': open('contrat.txt', 'rb')}
payload = {'username': 'achraf'}
response = requests.post(f"{BASE_URL}/sign", files=files, data=payload)
signature = response.json()['signature_hex']
print(f"Signature reçue : {signature[:30]}...")

# 4. Vérification (Cas Positif)
print("\n--- 3. Vérification du fichier original ---")
files = {'file': open('contrat.txt', 'rb')} # On renvoie le même fichier
payload = {
    'signature': signature,
    'public_key': ma_cle_publique
}
response = requests.post(f"{BASE_URL}/verify", files=files, data=payload)
print("Résultat :", response.json())

# 5. Vérification (Cas Négatif - HACKER)
print("\n--- 4. Tentative de piratage (Modification du fichier) ---")
with open("contrat.txt", "w") as f:
    f.write("Je soussigne, devoir 999999 euros.") # Modification !

files = {'file': open('contrat.txt', 'rb')}
response = requests.post(f"{BASE_URL}/verify", files=files, data=payload)
print("Résultat sur fichier modifié :", response.json())