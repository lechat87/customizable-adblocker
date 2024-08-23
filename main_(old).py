import socket
from scapy.all import *
import re

# Liste des domaines Family Link et de publicité
FAMILY_LINK_DOMAINS = ["familylink.google.com"]
AD_DOMAINS = ["doubleclick.net", "ads.google.com", "region1.google-analytics.com"]

# Fonction pour gérer la modification des paquets
def handle_packet(packet):
    # Vérifier si c'est un paquet DNS pour identifier le domaine
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # C'est une requête DNS
        query_name = packet[DNSQR].qname.decode('utf-8')
        print(f"\nRequête DNS: {query_name}")
        
        # Vérifier si c'est un paquet Family Link
        if any(domain in query_name for domain in FAMILY_LINK_DOMAINS):
            print("Paquet Family Link détecté")
            decision = input("Voulez-vous modifier ce paquet Family Link ? (y/n): ").strip().lower()
            
            if decision == 'y':
                if packet.haslayer(Raw):
                    new_data = input("Entrez les nouvelles données : ")
                    packet[Raw].load = new_data.encode('utf-8')
                    del packet[IP].chksum  # Recalculer les checksums
                    del packet[UDP].chksum
                    packet = packet.__class__(bytes(packet))
                    print("Le paquet a été modifié et sera renvoyé.")
                else:
                    print("Aucune donnée brute à modifier.")
            else:
                print("Le paquet n'a pas été modifié.")
            
            # Renvoyer le paquet modifié
            send(packet)
        
        # Bloquer les paquets publicitaires
        elif any(domain in query_name for domain in AD_DOMAINS):
            print("Paquet publicitaire détecté, il sera bloqué.")
            # Ne pas renvoyer le paquet pour le bloquer
        else:
            # Renvoyer les paquets normaux
            send(packet)

# Fonction principale pour capturer les paquets sur l'interface réseau
def start_server(interface="wls3"):
    print(f"Serveur démarré sur l'interface {interface}")
    sniff(iface=interface, prn=handle_packet, store=0)

if __name__ == "__main__":
    # Démarrer le serveur sur l'interface réseau (par défaut wls3)
    start_server(interface="wls3")

