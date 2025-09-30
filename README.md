# DDoS AI and Crypto Miner Protection

Acest proiect combina **inteligenta artificiala** cu monitorizarea proceselor pentru a oferi protectie in timp real impotriva atacurilor DDoS si a minerilor de criptomonede ascunsi.  
A fost realizat ca un instrument experimental de securitate pentru sisteme Linux, in cadrul unui hackathon.

---

## Ce face?

### 1. Protectie DDoS (AI)
- Foloseste un **autoencoder antrenat** pe trafic normal pentru a detecta anomalii in pachetele de retea  
- Monitorizeaza numarul de pachete TCP SYN, UDP și ICMP intr-o fereastra de timp glisanta  
- Calculeaza **MSE (Mean Squared Error)** intre datele reale si reconstructia autoencoder-ului  
- Daca eroarea depaseste un prag, semnalizeaza un posibil atac  
- Daca eroarea depaseste un prag critic, adresa IP sursa este **blocata automat** cu iptables pentru o perioada limitata 

### 2. Protectie impotriva minerilor de criptomonede
- Monitorizeaza toate procesele care ruleaza pe sistem  
- Identifica **mineri** cunoscuti (xmrig, cgminer, ethminer etc.)  
- Detecteaza procese cu **utilizare ridicata a CPU** pe perioade mai lungi  
- Monitorizeaza conexiunile de retea catre **porturi suspecte** (3333, 4444, 5555)  
- Procesele suspecte sunt automat **închise** si inregistrate in log  

---

## Cum rulezi

### Cerinte
- Python 3.8+  
- Drepturi de root (sudo) pentru a bloca IP-uri si a opri procese  

### 1. Protectia DDoS
```bash
pip3 install numpy tensorflow joblib scapy
sudo python3 ddos/ddos_detector.py
```

Scriptul:
- Asculta traficul pe interfata `wlan0` (se poate modifica în cod)  
- Detecteaza anomaliile si blocheaza automat IP-urile atacatorilor  

### 2. Protectia impotriva minerilor
```bash
pip3 install psutil
sudo python3 miner/miner_detector.py
```

Scriptul:
- Monitorizeaza procesele si conexiunile de retea  
- Opreste procesele suspecte si logheaza evenimentele in `/var/log/miner_detector.log`  

---

## Exemple de rulare

### DDoS AI
```
[ALERT] Flood from 192.168.0.15 MSE=25000.321
[ACTION] Blocked 192.168.0.15
```

### Miner detector
```
Oprit proces: PID=1234, name=xmrig, motiv: miner detectat (keyword)
Oprit proces: PID=5678, name=python3, motiv: consum CPU > 50% pentru 30s
```

## Limitari
- Necesita acces root pentru reguli firewall si managementul proceselor  
- Modelul AI trebuie antrenat pe trafic relevant pentru reteaua tinta  
- Detectia minerilor se bazeaza pe cuvinte cheie si networking, ceea ce poate genera fals pozitive  

