# Installation
sudo apt-get install hostapd bridge-utils

# Konfiguration
interfaces 	at 	/etc/network/interfaces
hostapd.conf    at 	/etc/hostapd.conf or /etc/hostapd/hostapd.conf

# Hostapd test
sudo hostapd -dd /etc/hostapd.conf

# Hostapd bei Systemstart
# Pfad zur Konfigurationsdatei eintragen
sudo nano /etc/init.d/hostapd
	DAEMON_CONF=/etc/hostapd.conf 
