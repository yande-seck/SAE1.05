import csv
import webbrowser
import matplotlib.pyplot as plt
from collections import Counter

# 1. Ouverture du fichier de capture de paquets
try:
    fichier = open("DumpFile.txt", "r")
except FileNotFoundError:
    print("Erreur : Le fichier 'Dumpfile05.txt' est introuvable.")
    exit()

# 2. Initialisation des listes et compteurs
ipsr, ipde, ports, flags, seq, ack, win, options, length, heure = [], [], [], [], [], [], [], [], [], []
flagcounterP, flagcounterS, flagcounter, framecounter, requestcounter, replycounter = 0, 0, 0, 0, 0, 0

# 3. Analyse du fichier de capture
for line in fichier:
    elements = line.split()
    
    if "IP" in elements:
        ipsr.append(elements[2])
        ipde.append(elements[4])
        ports.append(elements[2].split(":")[-1] if ":" in elements[2] else "")
        
        # Détection des drapeaux
        flag = "P" if "[P]" in line else "S" if "[S]" in line else "." if "[.]" in line else ""
        flags.append(flag)
        
        if flag == "P":
            flagcounterP += 1
        elif flag == "S":
            flagcounterS += 1
        elif flag == ".":
            flagcounter += 1
        
        seq.append(elements[elements.index("seq") + 1] if "seq" in elements else "")
        ack.append(elements[elements.index("ack") + 1] if "ack" in elements else "")
        win.append(elements[elements.index("win") + 1] if "win" in elements else "")
        options.append("nop,nop,TS" if "nop,nop,TS" in line else "")
        length.append(elements[-1])
        heure.append(elements[0])
        framecounter += 1
    
    if "ICMP" in elements:
        if "request" in elements:
            requestcounter += 1
        elif "reply" in elements:
            replycounter += 1

fichier.close()

# 4. Calcul des proportions pour les graphiques
globalflagcounter = flagcounter + flagcounterP + flagcounterS
globalreqrepcounter = replycounter + requestcounter

# 5. Création des graphiques (toujours générés, même si les données sont nulles)

# Graphique des drapeaux
plt.figure(figsize=(6, 6))
if globalflagcounter > 0:
    plt.pie([flagcounterP, flagcounterS, flagcounter], labels=["PUSH", "SYN", "ACK"], autopct='%1.1f%%')
    plt.title("Répartition des drapeaux")
else:
    plt.text(0.5, 0.5, "Aucun drapeau détecté", ha="center", va="center", fontsize=12)
    plt.title("Répartition des drapeaux (Aucune donnée)")
plt.savefig("graphe1.png")
plt.close()

# Graphique des requêtes et réponses ICMP
plt.figure(figsize=(6, 6))
if globalreqrepcounter > 0:
    plt.pie([requestcounter, replycounter], labels=["Requêtes", "Réponses"], autopct='%1.1f%%')
    plt.title("Répartition des requêtes et réponses ICMP")
else:
    plt.text(0.5, 0.5, "Aucune requête/réponse ICMP détectée", ha="center", va="center", fontsize=12)
    plt.title("Répartition des requêtes et réponses ICMP (Aucune donnée)")
plt.savefig("graphe2.png")
plt.close()

# 6. Écriture des données dans des fichiers CSV
with open('sae.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["DATE", "SOURCE", "PORT", "DESTINATION", "FLAG", "SEQ", "ACK", "WIN", "OPTIONS", "LENGTH"])
    for i in range(len(ipsr)):
        writer.writerow([heure[i], ipsr[i], ports[i], ipde[i], flags[i], seq[i], ack[i], win[i], options[i], length[i]])

with open('ds.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["Flag[P] (PUSH)", "Flag[S] (SYN)", "Flag[.] (ACK)", "Nombre total de trames", "nombre de request", "nombre de reply"])
    writer.writerow([flagcounterP, flagcounterS, flagcounter, framecounter, requestcounter, replycounter])

# 7. Création d'une page HTML pour afficher les graphiques
html_content = """
<html>
<head><title>Statistiques des paquets</title></head>
<body>
    <h1>Statistiques des drapeaux</h1>
    <img src="graphe1.png" alt="Graphique des drapeaux">
    <h1>Statistiques des requêtes et réponses ICMP</h1>
    <img src="graphe2.png" alt="Graphique des requêtes et réponses">
</body>
</html>
"""

with open("statistics.html", "w") as file:
    file.write(html_content)

# 8. Ouverture de la page HTML dans le navigateur
webbrowser.open("statistics.html")

print("\nAnalyse terminée. Les fichiers CSV et les graphiques ont été générés.")