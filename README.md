# go-ftproxy

Прозрачный FTP-прокси. Клиент подключается к прокси как к обычному FTP-серверу,
прокси соединяется с настоящим сервером и ретранслирует командный канал. Команды
не изменяются; исключение - `PORT`/`EPRT`/`PASV`/`EPSV`: адреса и порты в них
переписываются так, чтобы дата-соединения клиента и сервера тоже шли через
прокси. Иначе смысл ACL теряется - клиент мог бы передавать данные мимо прокси
напрямую.

Один процесс может слушать несколько портов; у каждого слушателя свой целевой
сервер, свой ACL и своя авторизация. IPv4-only: IPv6 отклоняется в конфиге, в
EPRT и в DNS (резолвятся только A-записи).

Данные не буферизуются - ретрансляция идёт чанками фиксированного размера, так
что многотерабайтные файлы не требуют ни лишней памяти, ни временных файлов на
диске.

## Сборка

Нужен Go 1.27+ (см. go.mod).

```
go build ./cmd/ftproxy           # локальная сборка
go test ./...
```

Кросс-сборка для Linux с любой платформы (cgo не используется, бинарник
статический, glibc не нужен):

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ftproxy ./cmd/ftproxy
```

Запуск: `./ftproxy -config config.yaml` (по умолчанию читается `config.yaml`).
Флаг `-version` печатает версию; при сборке её можно задать через
`-ldflags "-X main.version=... -X main.revision=..."`.
Остановка по SIGINT/SIGTERM graceful: слушатели закрываются, открытые сессии
долгие передачи не обрываются.

## Конфигурация

YAML; неизвестные поля - ошибка. Пример:

```yaml
log:
  level: info            # debug | info | warn | error
  format: text           # text | json
  output: stdout         # stdout | stderr | путь к файлу
  hide_passwords: false  # true: PASS/ACCT маскируются как ***** даже в debug;
                         # на info и выше пароли не пишутся и без этой опции

metrics:
  listen: "127.0.0.1:9105"   # /metrics и /healthz; пусто = выключено

dns:
  resolver: "10.10.0.53"     # свой DNS-сервер (не системный); пусто = системный
  timeout: 5s                # таймаут DNS-запроса
  cache_ttl: 60s             # кэш результатов; при отказе сервера отдаёт устаревший кэш

proxies:
  - name: public-mirror      # метка в логах и метриках
    listen: "192.168.10.5:21"          # адрес клиентского слушателя (IPv4)
    destination: "ftp.internal.example:21"  # целевой FTP-сервер (порт 21 по умолчанию)
    data_bind_address: "192.168.10.5"  # где поднимать дата-листенеры (по умолч. — адрес контроль-сокета)
    source_address: "192.168.10.5"     # source IP всех исходящих соединений (многохомный хост); по умолч. — по маршруту ОС
    external_ip: "203.0.113.10"        # какой IPv4 рекламировать клиенту в 227/PORT (NAT)
    passive_ports: "50000-50200"       # диапазон локальных дата-портов (опционально)
    control_idle_timeout: 30m          # простой контроль (приостанавливается на время передачи)
    data_accept_timeout: 60s           # сколько ждать подключения к дата-порту
    upstream_connect_timeout: 15s      # таймаут коннекта к целевому серверу
    auth:                              # опционально; без секции - полностью прозрачный прокси
      users:
        - username: marketing
          password: s3cret-2026
    acl:                               # опционально; без секции - разрешено всем
      default: deny                    # deny по умолчанию (рекомендуется)
      rules:
        - src: 192.168.10.0/24         # IPv4 CIDR или адрес
          dest: partner-origin.example:21  # CIDR против IP назначения либо "host[:port]"
          action: allow
```

Если секция `auth` есть, прокси принимает логин сам (до передачи команд на
сервер), затем прозрачно отправляет те же креды целевому серверу. Если её нет,
`USER`/`PASS` идут на сервер как есть и решение о доступе принимает сервер.

Правила ACL проверяются при каждом новом управляющем соединении, выигрывает
первое совпадение. `dest` с CIDR сравнивается с IP-адресами назначения,
разрешёнными через настроенный резолвер.

## Пассивный и активный режим

PASV/EPSV: ответ 227/229 перехватывается, прокси поднимает локальный
дата-листенер (на `data_bind_address`, в диапазоне `passive_ports`) и переписывает
адрес/порт в ответе. Клиент подключается к прокси, прокси - к серверу.
Клиентам извне через NAT нужен проброс не только порта контроля, но и
всего диапазона `passive_ports`; наружу прокси рекламирует `external_ip`.

PORT/EPRT: прокси поднимает листенер и сообщает серверу свой адрес вместо
адреса клиента; сервер подключается к прокси, прокси - к клиентскому endpoint
из исходного PORT/EPRT.

Дата-канал на каждую команду (RETR/STOR/LIST) свой, половинное закрытие (FIN)
доводится до обеих сторон. Сессия живёт, пока открыт контроль; при QUIT прокси
ждёт `221` от сервера перед закрытием.

## Логи

info - рабочий уровень: отказы ACL, ошибки подключения к серверу, сбои
дата-каналов, передачи (завершённые и оборванные) и все негативные ответы
FTP-сервера (4xx/5xx) с командой, которая их вызвала:

```
level=INFO msg="server error response" listener=mirror cmd="RETR file.xml" code=550 text="550 Failed to open file."
level=INFO msg="data transfer finished" listener=mirror cmd="RETR file.xml" mode=passive bytes_upload=0 bytes_download=6051
level=INFO msg="data transfer aborted" listener=mirror cmd="RETR big.zip" mode=passive bytes_upload=0 bytes_download=786913356 seconds=143 err="download write: connection reset by peer"
```

Передача считается завершённой, если дата-канал закрылся штатно (EOF с обеих
сторон). Иначе пишется `aborted` с причиной и фазой срыва: `read` - оборвался
источник данных (сервер при `RETR`, клиент при `STOR`), `write` - отказал
приёмник (клиент при `RETR`, сервер при `STOR`). Так видно, чья сторона
порвала соединение: обрыв на чтении из origin - сеть между прокси и сервером,
обрыв на записи к клиенту - клиент или его сегмент сети. Та же фаза идёт в
метрику `ftpproxy_data_errors_total{reason="transfer"}`.

debug дополнительно пишет весь FTP-диалог (`client cmd`, `server resp`,
переписанные 227/229) - им удобно разбирать проблемы с дата-каналами.

Пароли на info не попадают никогда. На debug видны только если не включён
`hide_passwords: true`; в записях об ошибках аргументы `PASS`/`ACCT` вырезаются
при любом уровне настроек.

## Метрики

`GET /metrics` (Prometheus) и `GET /healthz` на `metrics.listen`. Все метрики с
префиксом `ftpproxy_`, метка `listener` - это `name` из конфига:

| метрика | тип | что считает |
|---|---|---|
| `sessions_total{listener}` | counter | принятые клиентские соединения |
| `control_connections_active{listener}` | gauge | открытые контрольные соединения |
| `errors_total{listener,reason}` | counter | отказы (acl_denied, upstream_dial, ...) |
| `commands_total{listener,command}` | counter | команды FTP |
| `auth_failures_total{listener}` | counter | сбойные логины на прокси |
| `acl_denied_total{listener}` | counter | отказа ACL |
| `data_connections_total{listener,mode}` | counter | дата-соединения (active/passive) |
| `data_connections_active{listener}` | gauge | идущие передачи |
| `data_errors_total{listener,reason}` | counter | отказы дата-каналов |
| `data_bytes_total{listener,direction}` | counter | байты upload/download |
| `data_transfer_seconds{listener}` | histogram | длительность передач (бакеты до ~80 ч) |
| `build_info{version,revision}` | gauge | версия сборки |

Серии метрик по слушателям создаются при старте с нулями, кроме двухлейбловых
(`commands_total`, `errors_total`) - их лейблы известны только в рантайме.

## systemd

Готовый юнит - `deploy/ftproxy.service`. Установка:

```
sudo install -m 0755 ftproxy /usr/local/bin/ftproxy
sudo useradd --system --no-create-home --shell /usr/sbin/nologin ftproxy
sudo mkdir -p /etc/ftproxy
sudo install -m 0640 -o root -g ftproxy config.yaml /etc/ftproxy/config.yaml
sudo install -m 0644 deploy/ftproxy.service /etc/systemd/system/ftproxy.service
sudo systemctl daemon-reload && sudo systemctl enable --now ftproxy
```

Юнит работает непривилегированным пользователем; bind на порты <=1023
разрешён только `CAP_NET_BIND_SERVICE`. Песочница: `ProtectSystem=strict`,
`RestrictAddressFamilies=AF_INET` (ровно наш режим IPv4), `NoNewPrivileges` и
т.д. Логи в journald (в конфиге `log.output: stdout`). `TimeoutStopSec=30`,
чтобы идущие передачи успели штатно закрыться по SIGTERM. Быстрая проверка
установки на машине: `deploy/unit-smoke.sh`.

## Ограничения

- Везде только IPv4. IPv6 не поддерживается нигде и, скорее всего, поддержан
  не будет.
- FTPS/TLS нет. Прокси работает с открытым FTP; для шифрования - IPsec или
  VPN на сетевом уровне.
- ASCII-режим не транслируется: прокси не конвертирует `\r\n` в `\n` и обратно,
  данные идут байт в байт. Если это важно, используйте `TYPE I`.
- `EPSV ALL` отклоняется с 502 - после этой команды клиент ждёт, что все
  последующие PASV/EPSV будут по EPSV-формату, а прокси такого состояния не
  ведёт.
- Конфиг читается один раз при старте; изменения - через рестарт.

## Тесты

`go test ./...` покрывает: парсинг и переписывание PORT/EPRT/227/229, кадрирование
многострочных ответов сервера (`NNN-` ... `NNN `, у vsftpd так выглядит FEAT),
ACL
(первое совпадение, dest-CIDR по разрешённым IP, отказ IPv6), конфиг
(валидность, неизвестные поля, duration-форматы), DNS-резолвер (in-process
DNS-сервер, кэш, stale-fallback) и e2e-прогон с фейковым origin-сервером:
пассивные RETR/STOR, активный PORT, авторизация на прокси, deny по ACL,
отказ по плохому source_address, запись об обрыве передачи при сбросе
дата-канала клиентом.

## Авторы

- qwen3.8_flash_next - весь код, отладка, разбор продакшн-логов
- r2fn - постановка, окружение, эксплуатация
