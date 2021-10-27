# Izvještaj laboraotrijskih vježbi

# 1. Laboratorijska vježba

12.10.2021.

## Zadatak

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. 

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container):

- dvije žrtve station-1
- station-2
- napadač evil-station.

## Upoznavanje sa alatima

**Kloniranje repozitorija**

```bash
$ git clone https://github.com/mcagalj/SRP-2021-22
```

**Promjena radnog direktorija**

```bash
$ cd SRP-2021-22/arp-spoofing
```

**Buildanje i pokretanje docker kontejnera**

```bash
$ chmod +X ./start.sh
$ ./start.sh
```

**Zaustavljanje docker kontejnera**

```bash
$ chmod +X ./stop.sh
$ ./stop.sh
```

**Izlist pokrenutih kontejnera**

```bash
$ docker ps
```

```
CONTAINER ID   IMAGE     COMMAND   CREATED         STATUS         PORTS     NAMES
7142ae607cb3   srp/arp   "bash"    4 minutes ago   Up 4 minutes             station-2
c810f9effdb1   srp/arp   "bash"    4 minutes ago   Up 4 minutes             evil-station
cec29037dbe5   srp/arp   "bash"    4 minutes ago   Up 4 minutes             station-1
---------------------------------------------------------------------------------------
```

**Pokretanje interaktivnog shella u `station-1` kontejneru**

```bash
$ docker ps exec -it sh
```

**Dohvaćenje konfiguracije mrežnog interfejsa**

```bash
$ ifconfig -a
```

```
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500        inet 172.24.0.2  netmask 255.255.0.0  broadcast 172.24.255.255        ether 02:42:ac:18:00:02  txqueuelen 0  (Ethernet)        RX packets 68  bytes 8291 (8.2 KB)        RX errors 0  dropped 0  overruns 0  frame 0        TX packets 0  bytes 0 (0.0 B)        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536        inet 127.0.0.1  netmask 255.0.0.0        loop  txqueuelen 1000  (Local Loopback)        RX packets 0  bytes 0 (0.0 B)        RX errors 0  dropped 0  overruns 0  frame 0        TX packets 0  bytes 0 (0.0 B)        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Informacije koje dobivamo su:

- IP adresa: 172.24.0.2
- adresa mrežnog uređaja:  02:42:ac:18:00:02

**Provjerimo nalazi li se `station-2` na istoj mreži**

```bash
$ ping station-2
```

```
PING station-2 (172.24.0.4) 56(84) bytes of data.
64 bytes from station-2.srp-lab (172.24.0.4): icmp_seq=1 ttl=64 time=0.404 ms
64 bytes from station-2.srp-lab (172.24.0.4): icmp_seq=2 ttl=64 time=0.164 ms
64 bytes from station-2.srp-lab (172.24.0.4): icmp_seq=3 ttl=64 time=0.147 ms
64 bytes from station-2.srp-lab (172.24.0.4): icmp_seq=4 ttl=64 time=0.093 ms
64 bytes from station-2.srp-lab (172.24.0.4): icmp_seq=5 ttl=64 time=0.154 ms
```

**Pokretanje interaktivnog shella u `station-2` kontejneru**

```bash
$ docker exec -it station-2 sh
```

**Na kontejneru `station-1` pomoću netceta otvaramo server TCP socket na portu 9000**

```bash
$ netcat -lp 9000
```

**Na kontejneru `station-2` pomoću netcata otvaramo client TCP socket na hostnameu `statio-1` 9000**

```bash
$ netcat station-1 9000
```

**Pokretanje interaktivnog shella u `evil-station` kontejneru**

```bash
$ docker exec -it evil-station sh
```

## Izvršavanje napada

**U kontejneru `evil-station` pokrećemo arpspoof**

```bash
$ arpspoof -t station-1 station-2
```

**Pokrećemo tcpdump u kontejneru `evil-station` i pratimo promet**

```bash
$ tcpdump
```

**Gasimo prosljeđivanje spoofanih paketa**

```bash
$ echo 0 > /proc/sys/net/ipv4/ip_forward
```

# 2. Laboratorijska vježba

26.10.2021.

Pomoću programskog jezika Python i biblioteke `crypto` koristimo metode enkripcije o kojima smo učili na satu.

Zbog lakšeg *dependency managmenta* koristimo python virtualenvove.

Virtualno okruženje stvaramo komandom `pipenv shell`.

Kreirani su fileovi:

- `Pipfile`  popis paketa
- `Pipfile.lock` popis zakljucanih verzija instaliranih paketa

**Instaliramo paket `cryptography`**

```bash
pipenv install cryptography
```

Prvi koraci sa Fernetom.

```python
from cryptography.fernet import Fernet

PLAINTEXT = b"Hello world"

# generiramo enkripcijski ključ
key = Fernet.generate_key()

# kreiramo instancu Fernet klase
fernet = Fernet(key=key)

# enkriptiramo vrijednost variable PLAINTEXT
ciphertext = fernet.encrypt(PLAINTEXT)

# dekriptiramo ciphertext
deciphertext = fernet.decrypt(ciphertext)

print(f"{ciphertext}\n : \n{deciphertext}")
```

Koristeći poznatu metodu hashiranja, pronalazimo hash stringa `josip_bartulovic`.

Nakon toga unutar foldera pronalazimo file kojem ime odgovara tom hashu.

```python
from cryptography.hazmat.primitives import hashes
import binascii

def hash(input):
    if not isinstance(input, bytes):
        input = input.encode()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(input)
    hash = digest.finalize()

    return hash.hex()

filename = hash('prezime_ime') + ".encrypted"

if __name__ == "__main__":
    print(hash("bartulovic_josip"))
```

Idući zadatak je brute forceom saznati enkripcijski ključ maksimalne entropije 22.

```python
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken, Fernet
import base64
from concurrent.futures import ProcessPoolExecutor, as_completed

def keys(range_from, range_to):
    key = range_from
    print(f"{range_from} - {range_to}")
    while key <= range_to:
        key_bytes = key.to_bytes(32, "big")
        key_base64 = base64.urlsafe_b64encode(key_bytes)
        yield key_base64
        key += 1

def get_file_binary_header(filename="./file.encryption"):
    with open(filename, "rb") as file:
        return file.read()
    

def write_image_to_file(image, filename="./file.encryption.png"):
    with open(filename, "wb") as file:
        file.write(image)

def validate_png_header(png_bin):
    if png_bin[1:4] == b"PNG":
        return True
    return False

def _attack(from_pow, to_pow):
    file_content = get_file_binary_header()

    for index, key in enumerate(keys(from_pow, to_pow)):
        fernet = Fernet(key)

        if index % 1000 == 0:
            print(f"{index} - current - {key}")

        try:
            decypher = fernet.decrypt(file_content)
            if validate_png_header(decypher):
                print("FOUND IT")
                write_image_to_file(decypher)
                return True
        except InvalidToken:
            pass

def paralelize_attack():
    tasks = []
    spreads = [i for i in range(0, 2**22, (2**22)//8+1)]
    with ProcessPoolExecutor(max_workers=100) as executor:
        for spread_index in range(0, len(spreads)-1):
            tasks.append(
                executor.submit(
                    _attack, 
                    spreads[spread_index],
                    spreads[spread_index + 1],
                )
            )

        # prolazimo kroz sve taskove
        # kada prvi task završi cancelamo sve ostale
        for result in as_completed(tasks):
            print("DONE")
            for task in tasks:
                try:
                    task.cancel()
                except Exception:
                    pass

if __name__ == "__main__":
    paralelize_attack()
```
