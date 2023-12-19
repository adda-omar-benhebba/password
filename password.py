import re
import hashlib

def verifier_mot_de_passe(mot_de_passe):
    
    if len(mot_de_passe) < 8:
        return "Le mot de passe doit contenir au moins 8 caractères." 
    elif not re.search("[a-z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre minuscule." 
    elif not re.search("[A-Z]", mot_de_passe):
        return "Le mot de passe doit contenir au moins une lettre majuscule." 
    elif not re.search("[0-9]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un chiffre."  
    elif not re.search("[!@#$%^&*]", mot_de_passe):
        return "Le mot de passe doit contenir au moins un caractère spécial (!, @, #, $, %, ^, &, *)." 
    else:
        return "Le mot de passe est sécurisé." 


while True:
    mot_de_passe = input("Veuillez choisir un mot de passe: ")  
    resultat = verifier_mot_de_passe(mot_de_passe) 
    print(resultat)
    if resultat == "Le mot de passe est sécurisé.":
        break  

h = hashlib.sha256(mot_de_passe.encode()) 
mot_de_passe_crypte = h.hexdigest()  
print("Votre mot de passe crypté est : ", mot_de_passe_crypte) 