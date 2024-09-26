# Nmass

[![PyPI version](https://badge.fury.io/py/nmass.svg)](https://badge.fury.io/py/nmass) [![](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/) [![](https://img.shields.io/github/license/zrquan/nmass.svg)](https://github.com/zrquan/nmass/blob/main/LICENSE)

Nmass is a python3 library that makes it easier for developers to use **nmap and masscan**. It translates many and complex arguments into idiomatic methods and wraps the scan results in well-defined **pydantic** models.

## Examples

### Basic nmap example

``` python
# nmap_example.py
nm = (
    Nmap()
    .with_targets("172.18.0.2")
    .with_most_common_ports(100)
    .with_service_info()
    .with_default_script()
    .without_ping()
    .without_dns_resolution()
)
if result := nm.run(with_output=False):
    print(result.model_dump_json(exclude_none=True))
```

<details>
  <summary>python nmap_example.py | jq</summary>

  ``` json
  {
    "scanner": "nmap",
    "args": "/usr/bin/nmap -oX /tmp/tmpv7ici52_ --top-ports 100 -sV -sC -Pn -n 172.18.0.2",
    "start": "1722592782",
    "start_time": "Fri Aug  2 17:59:42 2024",
    "version": "7.95",
    "xmloutputversion": "1.05",
    "scaninfo": {
      "type": "connect",
      "protocol": "tcp",
      "numservices": "100",
      "services": "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    },
    "hosts": [
      {
        "status": {
          "state": "up",
          "reason": "user-set",
          "reason_ttl": "0"
        },
        "address": [
          {
            "addr": "172.18.0.2",
            "addrtype": "ipv4"
          }
        ],
        "hostnames": {},
        "ports": {
          "extraports": {
            "state": "closed",
            "count": "98"
          },
          "ports": [
            {
              "protocol": "tcp",
              "portid": 8009,
              "state": {
                "state": "open",
                "reason": "syn-ack",
                "reason_ttl": "0"
              },
              "service": {
                "name": "ajp13",
                "product": "Apache Jserv",
                "method": "probed",
                "confidence": "10"
              },
              "scripts": [
                {
                  "id": "ajp-methods"
                }
              ]
            },
            {
              "protocol": "tcp",
              "portid": 8080,
              "state": {
                "state": "open",
                "reason": "syn-ack",
                "reason_ttl": "0"
              },
              "service": {
                "name": "http",
                "product": "Apache Tomcat",
                "version": "8.5.19",
                "method": "probed",
                "confidence": "10",
                "cpe": "cpe:/a:apache:tomcat:8.5.19"
              },
              "scripts": [
                {
                  "id": "http-favicon"
                },
                {
                  "id": "http-title"
                }
              ]
            }
          ]
        },
        "times": {
          "srtt": "78",
          "rttvar": "71",
          "to": "100000"
        }
      }
    ],
    "stats": {
      "finished": {
        "time": "1722592788",
        "timestr": "Fri Aug  2 17:59:48 2024",
        "summary": "Nmap done at Fri Aug  2 17:59:48 2024; 1 IP address (1 host up) scanned in 6.21 seconds",
        "elapsed": "6.21",
        "exit": "success"
      },
      "hosts": {
        "up": "1",
        "down": "0",
        "total": "1"
      }
    }
  }
  ```
</details>

### Basic masscan example

``` python
# masscan_example.py
ms = (
    Masscan()
    .with_targets("183.2.172.185")
    .with_ports("80,443")
    .with_banner()
)
if result := ms.run(with_output=False):
    print(result.model_dump_json(exclude_none=True))
```

<details>
  <summary>sudo python masscan_example.py | jq</summary>

  ``` json
  {
    "scanner": "masscan",
    "start": "1722593029",
    "version": "1.0-BETA",
    "xmloutputversion": "1.03",
    "scaninfo": {
      "type": "syn",
      "protocol": "tcp"
    },
    "hosts": [
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 443,
              "state": {
                "state": "open",
                "reason": "syn-ack",
                "reason_ttl": "51"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 80,
              "state": {
                "state": "open",
                "reason": "syn-ack",
                "reason_ttl": "51"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 443,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "X509",
                "banner": "MIIETjCCAzagAwIBAgINAe5fFp3/lzUrZGXWajANBgkqhkiG9w0BAQsFADBXMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UECxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTE4MDkxOTAwMDAwMFoXDTI4MDEyODEyMDAwMFowTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMJXaQeQZ4Ihb1wIO2hMoonv0FdhHFrYhy/EYCQ8eyip0EXyTLLkvhYIJG4VKrDIFHcGzdZNHr9SyjD4I9DCuul9e2FIYQebs7E4B3jAjhSdJqYi8fXvqWaN+JJ5U4nwbXPsnLJlkNc96wyOkmDoMVxu9bi9IEYMpJpij2aTv2y8gokeWdimFXN6x0FNx04Druci8unPvQu7/1PQDhBjPogiuuU6Y6FnOM3UEOIDrAtKeh6bJPkC4yYOlXy7kEkmho5TgmYHWyn3f/kRTvriBJ/K1AFUjRAjFhGV64l++td7dkmnq/X8ET75ti+w1s4FRpFqkD2m7pg5NxdsZphYIXAgMBAAGjggEiMIIBHjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUj/BLf6guRSSuTVD6Y5qL3uLdG7wwHwYDVR0jBBgwFoAUYHtmGkUNl8qJUC99BM00qP/8/UswPQYIKwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290cjEwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBACNw6c/ivvVZrpRCb8RDM6rNPzq5ZBfyYgZLSPFAiAYXof6r0V88xjPy847dHx0+zBpgmYILrMf8fpqHKqV9D6ZX7qw7aoXW3r1AY/itpsiIsBL89kHfDwmXHjjqU5++BfQ+6tOfUBJ2vgmLwgtIfR4uUfaNU9OrH0Abio7tfftPeVZwXwzTjhuzp3ANNyuXlava4BJrHEDOxcd+7cJiWOx37XMiwor1hkOIreoTbv3Y/kIvuX1erRjvlJDKPSerJpSZdcfL03v3ykzTr1EhkluEfSufFT90y1HonoMOFm8b50bOI7355KKL0jlrqnkckSziYSQtjipIcJDEHsXo4HA="
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 443,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "X509",
                "banner": "MIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODExMjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uPUGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3idaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhMabO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1lVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cqo8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEAAaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANzEdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl06r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEwfpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMzhriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7eSPY="
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 443,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "ssl",
                "banner": "TLS/1.1 cipher:0xc011, baidu.com, baidu.com, baifubao.com, www.baidu.cn, www.baidu.com.cn, mct.y.nuomi.com, apollo.auto, dwz.cn, *.baidu.com, *.baifubao.com, *.baidustatic.com, *.bdstatic.com, *.bdimg.com, *.hao123.com, *.nuomi.com, *.chuanke.com, *.trustgo.com, *.bce.baidu.com, *.eyun.baidu.com, *.map.baidu.com, *.mbd.baidu.com, *.fanyi.baidu.com, *.baidubce.com, *.mipcdn.com, *.news.baidu.com, *.baidupcs.com, *.aipage.com, *.aipage.cn, *.bcehost.com, *.safe.baidu.com, *.im.baidu.com, *.baiducontent.com, *.dlnel.com, *.dlnel.org, *.dueros.baidu.com, *.su.baidu.com, *.91.com, *.hao123.baidu.com, *.apollo.auto, *.xueshu.baidu.com, *.bj.baidubce.com, *.gz.baidubce.com, *.smartapps.cn, *.bdtjrcv.com, *.hao222.com, *.haokan.com, *.pae.baidu.com, *.vd.bdstatic.com, *.cloud.baidu.com, click.hm.baidu.com, log.hm.baidu.com, cm.pos.baidu.com, wn.pos.baidu.com, update.pan.baidu.com"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 443,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "X509",
                "banner": "MIIJ7DCCCNSgAwIBAgIMTkADpl62gfh/S9jrMA0GCSqGSIb3DQEBCwUAMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yNDA3MDgwMTQxMDJaFw0yNTA4MDkwMTQxMDFaMIGAMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQMA4GA1UEBxMHYmVpamluZzE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20gU2NpZW5jZSBUZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1wFMskJ2dseOqoHptNwotFOhdBERsZ4VQnRNKXEEXMQEfgbNtScQ+C/Z+IpRAt1EObhYlifn74kt2nTsCQLngjfQkRVBuO/6PNGKdlCYGBeGqAL7xR+LOyHnpH9mwCBJc+WVt2zYM9I1clpXCJa+Itsq6qpb1AGoQxRDZ2n4K8Gd61wgNCPHDHc/Lk9NPJoUBMvYWvEe5lKhHsJtWtHe4QC3y58Vi+r5R0PWn2hyTBr9fCo58p/stDiRqp9Irtmi95YhwkNkmgwpMB8RhcGoNh+Uw5TkPZVj4AVaoPT1ED/GMKZev0+ypmp0+nmjVg2x7yUfLUfp3X7oBdI4TS2hvAgMBAAGjggaTMIIGjzAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADCBjgYIKwYBBQUHAQEEgYEwfzBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nyc2FvdnNzbGNhMjAxOC5jcnQwNwYIKwYBBQUHMAGGK2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzcnNhb3Zzc2xjYTIwMTgwVgYDVR0gBE8wTTBBBgkrBgEEAaAyARQwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQICMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAxOC5jcmwwggNhBgNVHREEggNYMIIDVIIJYmFpZHUuY29tggxiYWlmdWJhby5jb22CDHd3dy5iYWlkdS5jboIQd3d3LmJhaWR1LmNvbS5jboIPbWN0LnkubnVvbWkuY29tggthcG9sbG8uYXV0b4IGZHd6LmNuggsqLmJhaWR1LmNvbYIOKi5iYWlmdWJhby5jb22CESouYmFpZHVzdGF0aWMuY29tgg4qLmJkc3RhdGljLmNvbYILKi5iZGltZy5jb22CDCouaGFvMTIzLmNvbYILKi5udW9taS5jb22CDSouY2h1YW5rZS5jb22CDSoudHJ1c3Rnby5jb22CDyouYmNlLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIPKi5tYXAuYmFpZHUuY29tgg8qLm1iZC5iYWlkdS5jb22CESouZmFueWkuYmFpZHUuY29tgg4qLmJhaWR1YmNlLmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUuY29tgg4qLmJhaWR1cGNzLmNvbYIMKi5haXBhZ2UuY29tggsqLmFpcGFnZS5jboINKi5iY2Vob3N0LmNvbYIQKi5zYWZlLmJhaWR1LmNvbYIOKi5pbS5iYWlkdS5jb22CEiouYmFpZHVjb250ZW50LmNvbYILKi5kbG5lbC5jb22CCyouZGxuZWwub3JnghIqLmR1ZXJvcy5iYWlkdS5jb22CDiouc3UuYmFpZHUuY29tgggqLjkxLmNvbYISKi5oYW8xMjMuYmFpZHUuY29tgg0qLmFwb2xsby5hdXRvghIqLnh1ZXNodS5iYWlkdS5jb22CESouYmouYmFpZHViY2UuY29tghEqLmd6LmJhaWR1YmNlLmNvbYIOKi5zbWFydGFwcHMuY26CDSouYmR0anJjdi5jb22CDCouaGFvMjIyLmNvbYIMKi5oYW9rYW4uY29tgg8qLnBhZS5iYWlkdS5jb22CESoudmQuYmRzdGF0aWMuY29tghEqLmNsb3VkLmJhaWR1LmNvbYISY2xpY2suaG0uYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29tghBjbS5wb3MuYmFpZHUuY29tghB3bi5wb3MuYmFpZHUuY29tghR1cGRhdGUucGFuLmJhaWR1LmNvbTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAU+O9/8s14Z6jeb48kjYjxhwMCs+swHQYDVR0OBBYEFK3KAFTK2OWUto+D2ieAKE5ZJDsYMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgCvGBoo1oyj4KmKTJxnqwn4u7wiuq68sTijoZ3T+bYDDQAAAZCQAGzzAAAEAwBHMEUCIFwF5Jc+zyIFGnpxchz9fY1qzlqg/oVrs2nnuxcpBuuIAiEAu3scD6u51VOP/9aMSqR2yKHZLbHwFos9U7AzSdLIZa8AdgAS8U40vVNyTIQGGcOPP3oT+Oe1YoeInG0wBYTr5YYmOgAAAZCQAG3iAAAEAwBHMEUCIBBYQ6NP7VUDgfktWRg5QxT23QAbTqYovtV2D9O8Qc0TAiEA2P7+44EvQ5adwL1y56oyxv/m+Gujeia7wpo7+Xbhv6MAdwAN4fIwK9MNwUBiEgnqVS78R3R8sdfpMO8OQh60fk6qNAAAAZCQAGy+AAAEAwBIMEYCIQDU7Hxtx4c9p9Jd+cr+DCMtyRYSc0b8cktCcbMmtDE9ygIhAIpJd4yb7jtxnaEC8oLWDushbK1v0BIuZu6YrQvsf1nQMA0GCSqGSIb3DQEBCwUAA4IBAQCh9DfewC012/+fHZpmSpCny+h3/+ClAZ8cJVO+LCmYz9r6bkyhcFquJ5qUpyoW8AYtU0oUFlqH6zLIyujW+7lqwFxB6NsXKKdwBKmMbmnZr2Fca5f+TtwD/GDJgG/egr7fI1u8194j9KEl8cK8Fujm+UsoWklEzd1It9xkLazJR/6SwbhSR4k610pvj8rQrS4wAewuYFDaDOfqsHtDIsx1tZfIfoB/O1wGWZQJU2M9wC8uYq0jQ2Q0MQJXuyJz04MFiGrPAS1Uk8mWd8M+3p65Xy4iAf8uWzs1M+fcwBE8BNBghkQgE+FSUsldm+5ZBCazU0joJswzldWisXMLTagI"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 80,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "http.server",
                "banner": "BWS/1.1"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 80,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "title",
                "banner": "\\xe7\\x99\\xbe\\xe5\\xba\\xa6\\xe4\\xb8\\x80\\xe4\\xb8\\x8b\\xef\\xbc\\x8c\\xe4\\xbd\\xa0\\xe5\\xb0\\xb1\\xe7\\x9f\\xa5\\xe9\\x81\\x93"
              }
            }
          ]
        }
      },
      {
        "address": [
          {
            "addr": "183.2.172.185",
            "addrtype": "ipv4"
          }
        ],
        "ports": {
          "ports": [
            {
              "protocol": "tcp",
              "portid": 80,
              "state": {
                "state": "open",
                "reason": "response",
                "reason_ttl": "51"
              },
              "service": {
                "name": "http",
                "banner": "HTTP/1.0 200 OK\\x0d\\x0aBdpagetype: 1\\x0d\\x0aBdqid: 0xdf61c4a5002795cb\\x0d\\x0aContent-Length: 404068\\x0d\\x0aContent-Type: text/html; charset=utf-8\\x0d\\x0aDate: Fri, 02 Aug 2024 10:03:52 GMT\\x0d\\x0aP3p: CP=\\x22 OTI DSP COR IVA OUR IND COM \\x22\\x0d\\x0aP3p: CP=\\x22 OTI DSP COR IVA OUR IND COM \\x22\\x0d\\x0aServer: BWS/1.1\\x0d\\x0aSet-Cookie: BAIDUID=C5A9F500C6C4FD8A947229883DFA4F38:FG=1; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com\\x0d\\x0aSet-Cookie: BIDUPSID=C5A9F500C6C4FD8A947229883DFA4F38; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com\\x0d\\x0aSet-Cookie: PSTM=1722593032; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com\\x0d\\x0aSet-Cookie: BAIDUID=C5A9F500C6C4FD8ADFE948AE028E33E7:FG=1; max-age=31536000; expires=Sat, 02-Aug-25 10:03:52 GMT; domain=.baidu.com; path=/; version=1; comment=bd\\x0d\\x0aSet-Cookie: BDSVRTM=1; path=/\\x0d\\x0aSet-Cookie: BD_HOME=1; path=/\\x0d\\x0aStrict-Transport-Security: max-age=0\\x0d\\x0aTraceid: 1722593032023886746616096362756150105547\\x0d\\x0aVary: Accept-Encoding\\x0d\\x0aX-Ua-Compatible: IE=Edge,chrome=1\\x0d\\x0aX-Xss-Protection: 1;mode=block\\x0d\\x0a\\x0d"
              }
            }
          ]
        }
      }
    ],
    "stats": {
      "finished": {
        "time": "1722593041",
        "timestr": "2024-08-02 18:04:01",
        "elapsed": "12"
      },
      "hosts": {
        "up": "2",
        "down": "0",
        "total": "2"
      }
    }
  }
  ```
</details>

### More?

Masscan is fast, and nmap is powerful. Why not combine the two?🤩 Start by using masscan to quickly detect open ports in bulk, then use nmap to perform in-depth scans on these open ports!

```python
# This is just an example, is not recommended to run
step1 = (
    Masscan()
    .with_targets("10.0.0.0/8")
    .with_ports(80, 443)
    .with_rate(10000)
)
step2 = (
    Nmap()
    .with_step(step1.run())
    .with_service_info()
    .with_scripts("http-title")
    .with_verbose()
)
retult = step2.run()
```

## Thanks

- [Ullaakut/nmap](https://github.com/Ullaakut/nmap) - Provided design inspiration.
- [savon-noir/python-libnmap](https://github.com/savon-noir/python-libnmap) - Provided test data.
