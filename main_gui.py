import socket
from scapy.all import *
import re
import threading
import customtkinter as ctk

topmost = 0
blocked_ads = 0

def load_ad_domains(file_path):
    ad_domains = []
    try:
        with open(file_path, 'r') as file:
            ad_domains = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Le fichier {file_path} n'a pas été trouvé.")
    return ad_domains

# Charger les domaines de publicité depuis le fichier
AD_DOMAINS = load_ad_domains('.AD_DOMAINS')
FAMILY_LINK_DOMAINS = ["familylink.google.com"]

class DNSInterceptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("DNS Interceptor")
        self.geometry("600x400")
        self.interface = ctk.StringVar(value="wls3")
        self.server_thread = None
        self.server_running = threading.Event()

        # Interface graphique
        self.create_widgets()

    def create_widgets(self):
        # Titre
        self.label = ctk.CTkLabel(self, text="DNS Interceptor", font=("Arial", 20))
        self.label.pack(pady=10)

        # Entrée pour l'interface réseau
        self.interface_label = ctk.CTkLabel(self, text="Interface réseau:")
        self.interface_label.pack(pady=5)
        self.interface_entry = ctk.CTkEntry(self, textvariable=self.interface)
        self.interface_entry.pack(pady=5)
        
        self.ad_counter = ctk.CTkLabel(self, text=f"Nombre de pubs bloqués : {blocked_ads} !")
        self.ad_counter.pack(pady=5)
        self.ad_counter.place(x=10, y=5)

        # Boutons démarrer/arrêter
        self.start_button = ctk.CTkButton(self, text="Démarrer", command=self.start_server)
        self.start_button.pack(pady=5)

        self.stop_button = ctk.CTkButton(self, text="Arrêter", command=self.stop_server, state="disabled")
        self.stop_button.pack(pady=5)
        
        self.wh_window = ctk.CTkButton(self, text="Premier plan", command=self.wh_window)
        self.wh_window.pack(pady=5)

        # Affichage des logs
        self.log_text = ctk.CTkTextbox(self, width=550, height=200)
        self.log_text.pack(pady=10)
        
    def log(self, message):
        self.log_text.insert(ctk.END, message + "\n")
        self.log_text.see(ctk.END)

    def handle_packet(self, packet):
        global blocked_ads
        # Vérifier si c'est un paquet DNS pour identifier le domaine
        if packet.haslayer(DNS) and packet[DNS].qr == 0:  # C'est une requête DNS
            query_name = packet[DNSQR].qname.decode('utf-8')
            self.log(f"Requête DNS: {query_name}")
            
            # Vérifier si c'est un paquet Family Link
            if any(domain in query_name for domain in FAMILY_LINK_DOMAINS):
                self.log("Paquet Family Link détecté")
                
                # Initialiser current_data à une chaîne vide par défaut
                current_data = ""
                
                # Afficher les données actuelles du paquet si disponibles
                if packet.haslayer(Raw):
                    current_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    self.log(f"Données actuelles du paquet: {current_data}")
                
                # Demander si on veut modifier le paquet
                if self.ask_modify_packet(current_data):
                    if packet.haslayer(Raw):
                        new_data = self.ask_new_data(current_data)
                        packet[Raw].load = new_data.encode('utf-8')
                        
                        # Recalculer les checksums si nécessaire
                        if packet.haslayer(IP):
                            del packet[IP].chksum
                        if packet.haslayer(UDP):
                            del packet[UDP].chksum
                        elif packet.haslayer(TCP):
                            del packet[TCP].chksum
                        
                        packet = packet.__class__(bytes(packet))
                        self.log("Le paquet a été modifié et sera renvoyé.")
                    else:
                        self.log("Aucune donnée brute à modifier.")
                    
                    send(packet)
                else:
                    self.log("Le paquet n'a pas été modifié.")
            # Bloquer les paquets publicitaires
            elif any(domain in query_name for domain in AD_DOMAINS):
                blocked_ads += 1
                self.log(f"Paquet publicitaire détecté !")
                self.ad_counter.configure(text=f"Nombre de pubs bloqués : {blocked_ads} !")
                # Ne pas renvoyer le paquet pour le bloquer
            else:
                # Renvoyer les paquets normaux
                send(packet)

    def ask_modify_packet(self, current_data):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Modification du Paquet")
        
        label = ctk.CTkLabel(dialog, text="Voulez-vous modifier ce paquet Family Link ?")
        label.pack(pady=10)
        
        data_label = ctk.CTkLabel(dialog, text=f"Données actuelles :\n{current_data}", justify="left")
        data_label.pack(pady=10)
        
        button_frame = ctk.CTkFrame(dialog)
        button_frame.pack(pady=10)

        yes_button = ctk.CTkButton(button_frame, text="Oui", command=lambda: self._set_response(dialog, True))
        yes_button.pack(side="left", padx=5)

        no_button = ctk.CTkButton(button_frame, text="Non", command=lambda: self._set_response(dialog, False))
        no_button.pack(side="left", padx=5)

        dialog.transient(self)
        dialog.grab_set()
        self.wait_window(dialog)
        return self._response

    def ask_new_data(self, current_data):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Modification des données")

        label = ctk.CTkLabel(dialog, text=f"Données actuelles :\n{current_data}")
        label.pack(pady=10)

        entry = ctk.CTkEntry(dialog)
        entry.insert(0, current_data)  # Insérer les données actuelles dans l'entrée
        entry.pack(pady=10)

        button_frame = ctk.CTkFrame(dialog)
        button_frame.pack(pady=10)

        ok_button = ctk.CTkButton(button_frame, text="OK", command=lambda: self._set_response(dialog, entry.get()))
        ok_button.pack(side="left", padx=5)

        dialog.transient(self)
        dialog.grab_set()
        self.wait_window(dialog)
        return self._response

    def _set_response(self, dialog, response):
        self._response = response
        dialog.destroy()
        
    def wh_window(self):
        global topmost
        if topmost == 1:
            self.attributes('-topmost', False)
            self.wh_window.configure(text="Premier plan")
            topmost = 0
        else:
            self.attributes('-topmost', True)
            self.wh_window.configure(text="Arrière plan")
            topmost = 1

    def start_server(self):
        if not self.server_thread or not self.server_thread.is_alive():
            AD_DOMAINS = load_ad_domains('.AD_DOMAINS')
            self.server_running.set()
            self.server_thread = threading.Thread(target=self.server_loop)
            self.server_thread.start()
            self.log("Serveur démarré.")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.interface_entry.configure(state='disabled')

    def stop_server(self):
        if self.server_thread and self.server_thread.is_alive():
            self.server_running.clear()
            self.server_thread.join()
            self.log("Serveur arrêté.")
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            
    def server_loop(self):
        sniff(iface=self.interface.get(), prn=self.handle_packet, store=0, stop_filter=lambda _: not self.server_running.is_set())

# Exécution de l'application
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    app = DNSInterceptorApp()
    app.mainloop()

