# Stormshield SNS IP → Firewall Rule Lookup

Shell script Stormshield SNS környezethez, amely egy IP-cím listából kiindulva megkeresi:

1. az IP-hez tartozó `host` objektumot,
2. az objektumhoz tartozó közvetlen és group-on keresztüli konfigurációs hivatkozásokat,
3. az érintett Filter és NAT szabályokat,
4. majd a szabályokat CSV formátumba exportálja.

A script közvetlenül a Stormshield NS-BSD shell környezetében fut, és a beépített `nsrpc` klienssel kommunikál az SRP interface-szel.

## Működési modell

```text
IP-cím
  │
  ▼
CONFIG OBJECT LIST
  │
  └── Host objektum neve
         │
         ▼
CONFIG OBJECT HOST CHECK
         │
         ├── közvetlen használat
         ├── Group tagság
         └── érintett ruleid-k
                │
                ▼
CONFIG FILTER EXPLICIT
                │
                ├── Filter
                └── NAT
                │
                ▼
             CSV
```

A `HOST CHECK` azért fontos, mert nem csak a host közvetlen használatát vizsgálja, hanem a group-okon keresztüli érintettséget is.

## Követelmények

A scriptet olyan Stormshield SNS környezetben terveztük, ahol rendelkezésre áll:

- `/bin/sh`
- `awk`
- `sed`
- `cat`
- `rm`
- `nsrpc`

A scriptnek nincs szüksége Pythonra, Perlre vagy `expect`-re.

A lekérdezés az `nsrpc` `-c`, `-t` és `-l` lehetőségeit használja.

## Fájlok

Alapértelmezés szerint a script az alábbi fájlokat használja:

```text
/tmp/ips.txt
/tmp/firewall-config
/tmp/firewall-rules.csv
```

### `/tmp/ips.txt`

Egy IP-cím soronként:

```text
192.168.1.1
192.168.1.2
192.168.1.3
```

Üres sorok és `#` karakterrel kezdődő komment sorok figyelmen kívül maradnak.

Példa:

```text
# Servers
192.168.1.1
192.168.1.2

# Printers
192.168.1.50
```

### `/tmp/firewall-config`

Az `nsrpc -t` target fájlja.

A Stormshield `nsrpc` formátuma:

```text
IP[;port];login;password
```

A lokális SRP kapcsolat például:

```text
127.0.0.1;1300;admin;JELSZO
```

A fájlt megfelelő jogosultságokkal kell védeni, mert a jelszó ebben a fájlban szerepel.

Javasolt:

```sh
chmod 600 /tmp/firewall-config
```

### `/tmp/firewall-rules.csv`

A végső kimenet.

A CSV fejléc:

```text
LINE;RULEID;POSITION;RULE
```

Egy sor egy lekérdezett szabályt jelent.

## Telepítés

A scriptet például ide lehet menteni:

```text
/tmp/fw-object-rules.sh
```

A Stormshield környezetben a scriptet explicit shellből kell futtatni:

```sh
/bin/sh /tmp/fw-object-rules.sh
```

A közvetlen:

```sh
/tmp/fw-object-rules.sh
```

futtatás az SNS környezetben `Authentication error` hibát okozhat.

## Futtatás

Alapértelmezett fájlokkal:

```sh
/bin/sh /tmp/fw-object-rules.sh
```

A futás végén a CSV itt található:

```text
/tmp/firewall-rules.csv
```

## Feldolgozási lépések

### 1. IP → host objektum

Minden IP-hez létrejön egy Stormshield CLI parancs:

```text
CONFIG OBJECT LIST type=host start=0 search=<IP> searchfield=ip
```

Például:

```text
CONFIG OBJECT LIST type=host start=0 search=192.168.1.2 searchfield=ip
```

Eredmény:

```text
type="host" global=0 name="korte" ip="192.168.1.2" ...
```

A script ebből az objektum nevét eltárolja.

### 2. Host CHECK

A host objektumra a script kiadja:

```text
CONFIG OBJECT HOST CHECK name=korte
```

A Stormshield ebből megadja:

- a group tagságot,
- a konfigurációs modult,
- a slotot,
- a line-t,
- a rule ID-t.

Példa:

```text
[Group]
Group=palinka

[Configuration]
module=Filter slot=01 line=7 ruleid=5
module=Filter slot=01 line=5 ruleid=3
module=Filter slot=01 line=8 ruleid=6
```

Ez azt jelenti, hogy a `korte` objektumhoz kapcsolódóan három érintett szabályt találtunk, köztük a `palinka` group-on keresztüli szabályokat is.

### 3. Rule lekérdezés

A kapott `module + ruleid` kombinációkból a script egyedi lekérdezéseket készít.

Filter esetén:

```text
CONFIG FILTER EXPLICIT index=1 type=filter start=0 search="*ruleid=5*"
```

NAT esetén:

```text
CONFIG FILTER EXPLICIT index=1 type=nat start=0 search="*ruleid=5*"
```

Ugyanazt a `module + ruleid` kombinációt csak egyszer kérdezzük le.

### 4. CSV előállítása

A végső CSV-ben szabályonként egy sor szerepel:

```text
LINE;RULEID;POSITION;RULE
```

A `LINE`, `RULEID` és `POSITION` a policy szabály azonosítására szolgál, a `RULE` pedig a Stormshield által visszaadott szabályszöveg.

## Group kezelés

A script egyik fontos funkciója, hogy a host közvetlen használatán túl a group-on keresztüli használatot is figyelembe veszi.

Példa:

```text
korte
  └── palinka
```

Ha a `korte` hostot egy szabály közvetlenül használja:

```text
pass from korte to any
```

akkor ez a szabály releváns.

Ha egy másik szabály a `palinka` group-ot használja:

```text
pass from palinka to any
```

akkor az a `korte` IP-je szempontjából szintén releváns.

A script ezt a `CONFIG OBJECT HOST CHECK` eredménye alapján kezeli.

## Duplikáció kezelés

Ugyanaz a szabály több host szempontjából is releváns lehet. A rule lekérdezéseknél a `module + ruleid` kombinációkat deduplikáljuk, ezért ugyanazt a szabályt nem kell többször lekérdezni.

A végső CSV-ben egy lekérdezett szabály egy sort képvisel.

## Ideiglenes fájlok

A script futás közben egy egyedi munkafájl-prefixet használ:

```sh
WORK="/tmp/fwquery.$$"
```

A `$$` az aktuális shell process ID-je.

A script futás közben több ideiglenes command, output és mapping fájlt használ. A `cleanup` függvény ezeket a futás végén törli.

A takarítás normál kilépéskor és több megszakítási esetben is lefut.

## nsrpc működés

A script nem interaktív `SRPClient>` sessiont kezel közvetlenül.

Az `nsrpc` command file alapú módját használja:

```sh
nsrpc -c "$CMD_FILE" -t "$TARGET_FILE" -l "$OUTPUT_FILE"
```

A folyamat:

```text
command file
      │
      ▼
    nsrpc
      │
      ▼
   SRP interface
      │
      ▼
 log/output file
```

Ez lehetővé teszi, hogy a Stormshielden belül, kizárólag shellből automatizáljuk a lekérdezést.

## Biztonság

### Jelszó

A `firewall-config` target fájl tartalmazza a Stormshield hitelesítési adatokat:

```text
127.0.0.1;1300;admin;JELSZO
```

Ezért a fájl védelmét biztosítani kell:

```sh
chmod 600 /tmp/firewall-config
```

### Ideiglenes fájlok

A script `umask 077` beállítást használ, így a létrehozott ideiglenes fájlok szűkebb jogosultságokkal készülnek.

### Lekérdezési mód

A script rendeltetése konfiguráció-lekérdezés és riportolás. A feldolgozás során használt parancsok:

```text
CONFIG OBJECT LIST
CONFIG OBJECT HOST CHECK
CONFIG FILTER EXPLICIT
```

A script nem módosítja a firewall policy-t.

## Teljesítmény

A script több lépcsőben dolgozik.

### Első fázis

IP-címenként létrejön egy `CONFIG OBJECT LIST` lekérdezés.

### Második fázis

Az azonos host objektumokat deduplikáljuk, ezért egy hosthoz csak egy `CONFIG OBJECT HOST CHECK` lekérdezés készül.

### Harmadik fázis

A `module + ruleid` kombinációkat deduplikáljuk, ezért ugyanazt a Filter vagy NAT szabályt csak egyszer kérjük le.

Ez csökkenti az SRP lekérdezések számát.

Nagy IP-listák esetén azonban a konfigurációs lekérdezések száma jelentős lehet. A scriptet ezért célszerű először kisebb tesztlistával kipróbálni, majd nagyobb listákra fokozatosan kiterjeszteni.

## Példa

Bemenet:

```text
192.168.1.1
192.168.1.2
192.168.1.3
```

Host objektumok:

```text
192.168.1.1 -> alma
192.168.1.2 -> korte
192.168.1.3 -> szilva
```

A `korte` ellenőrzése:

```text
CONFIG OBJECT HOST CHECK name=korte
```

például:

```text
[Group]
Group=palinka

[Configuration]
module=Filter slot=01 line=7 ruleid=5
module=Filter slot=01 line=5 ruleid=3
module=Filter slot=01 line=8 ruleid=6
```

A lekérdezett szabályok:

```text
CONFIG FILTER EXPLICIT index=1 type=filter start=0 search="*ruleid=5*"
CONFIG FILTER EXPLICIT index=1 type=filter start=0 search="*ruleid=3*"
CONFIG FILTER EXPLICIT index=1 type=filter start=0 search="*ruleid=6*"
```

A CSV például:

```text
LINE;RULEID;POSITION;RULE
7;5;7;usage=0 match=0 ruleid=5: pass from korte to any ...
5;3;5;usage=0 match=0 ruleid=3: block from alma to palinka ...
8;6;8;usage=0 match=0 ruleid=6: pass from palinka to any ...
```

## Korlátok és továbbfejlesztési lehetőségek

A jelenlegi változat a `HOST CHECK` által visszaadott `module` érték alapján kezeli a `Filter` és `NAT` ágakat. A NAT kezelést célszerű külön, tényleges NAT szabályt tartalmazó tesztesettel is validálni.

Nagy IP-listák esetén további optimalizáció lehet:

- batch-ek használata,
- batch-ek közötti rövid késleltetés,
- részletes futásidő mérés,
- részletesebb hibajelzés,
- több policy slot kezelése,
- külön Filter és NAT riport,
- CSV helyett strukturáltabb export.

## Hibaelhárítás

### `Authentication error`

Ha ezt kapod:

```text
Authentication error
```

a scriptet ne közvetlenül indítsd:

```sh
/tmp/fw-object-rules.sh
```

hanem:

```sh
/bin/sh /tmp/fw-object-rules.sh
```

### Nincs host találat

Ellenőrizd kézzel:

```text
CONFIG OBJECT LIST type=host start=0 search=192.168.1.2 searchfield=ip
```

### Nincs szabály

Ellenőrizd:

```text
CONFIG OBJECT HOST CHECK name=korte
```

és nézd meg, hogy van-e benne:

```text
module=...
ruleid=...
```

### Rule lookup ellenőrzése

Például:

```text
CONFIG FILTER EXPLICIT index=1 type=filter start=0 search="*ruleid=5*"
```

## Licence és felelősség

Ez a script konfiguráció-lekérdezési és riportolási célú segédeszköz.

A scriptet használó adminisztrátor felelőssége:

- a megfelelő Stormshield jogosultságok használata,
- a hitelesítési adatok védelme,
- a lekérdezések hatásának ellenőrzése,
- a saját SNS verzióval történő kompatibilitás tesztelése.

A script nem tekinthető a Stormshield hivatalos termék-komponensének.

## Verzió

Kezdeti változat.

A jelenlegi script az alábbi Stormshield/SNS környezetben lett kialakítva:

```text
NS-BSD
4.2.4
amd64
```

A pontos CLI-viselkedés és az `nsrpc` támogatott opciói firmware-verziótól függhetnek.

