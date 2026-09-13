# skeltahtls

requests-подобный HTTP-клиент с точным TLS/HTTP2-отпечатком браузера. Форк `tls_client` / `tls_client2`
поверх Go-библиотеки [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client), с бинарниками,
собранными из исходников актуального тега (сейчас **v1.16.0**, профиль по умолчанию **`chrome_152`**).

```python
from skeltahtls import Session, AsyncSession

s = Session()                                  # chrome_152, random extension order как у настоящего Chrome
r = s.get("https://tls.peet.ws/api/all", headers={...})
r.json()["tls"]["ja4"]                         # t13d1517h2_8daaf6152771_cb7bf5808d99  == Google Chrome 152
```

## Установка

```bash
pip install skeltahtls                                                # PyPI
pip install git+https://github.com/skeltah/skeltahtls.git             # прямо из репозитория (нужен git)
pip install git+https://github.com/skeltah/skeltahtls.git@v1.16.0.2   # конкретная версия
pip install -e .                                                      # dev-режим из клона
```

Wheel один на все платформы (~40 МБ, бинарники внутри).

Платформы: Windows x64/x86, Linux x64 (glibc ≥ 2.17 и musl/alpine), Linux arm64/armv7, macOS arm64/x64.
Свою сборку библиотеки можно подсунуть через `SKELTAHTLS_LIBRARY=/path/to/lib.so`.

## Что отличается от tls_client / tls_client2

| Было | Стало |
|---|---|
| DLL v1.11.0 (авг 2025), максимум `chrome_133` | v1.16.0 из исходников: `chrome_150/152 (+_PSK)`, `brave_146`, `firefox_148`, `safari_ios_26_0` |
| `ja3_string` без `client_identifier` **молча игнорировался** (уходил `chrome_124`) | `ja3_string` → кастомный клиент; профиль + кастомные опции вместе → `SessionConfigurationError` |
| Кастомный JA3 требовал вручную задать sigalgs, versions, key shares, ALPN, ALPS, cert compression, trust anchors | Незаданные поля заполняются значениями Chrome 152 — голый JA3 Chrome даёт тот же JA4, что и профиль |
| Заголовки не из `header_order` сортировались **по алфавиту** | По умолчанию порядок = порядок ключей в dict; `header_order` можно передавать и в запросе |
| `force_http1`, профиль, таймаут после первого запроса **не менялись** (Go кэширует клиент по sessionId) | Изменение любой transport-опции пересоздаёт Go-клиент; куки при этом не теряются |
| Куки всего jar отправлялись на любой хост; `etsy.com`/`.etsy.com`/без домена — три разные куки, все уходили в запрос | `CookieJar` с идентичностью (name, domain, path); в запрос — одна кука на имя, самая специфичная; загрузка/выгрузка browser-export |
| Async: `verify` был инвертирован (сертификаты не проверялись), `allow_redirects=False`, нет `proxies`/`header_order` | Тот же интерфейс, что у `Session`; `async with`, общий пул потоков |
| `certCompressionAlgo`, `withDefaultCookieJar`, `additionalDecode` — устаревшие ключи API | Актуальные ключи v1.16: `certCompressionAlgos`, `withCustomCookieJar`, `timeoutMilliseconds`, `disableHttp3`, `disableSessionTickets`, `requestHostOverride`, `trustAnchorsPayload`, ... |
| `pseudo_header_order` с профилем — тихо игнорировался | Профили содержат свой порядок (Chrome: `m,a,s,p`); несовпадающий → ошибка сразу |
| Зависимость от `requests` (только ради `HTTPError`) | Без зависимостей |

## Использование

```python
s = Session(
    client_identifier="chrome_152",     # по умолчанию; skeltahtls.CHROME_LATEST
    random_tls_extension_order=True,    # по умолчанию; Chrome перемешивает расширения на каждом соединении
    proxy="socks5://user:pass@host:port",
    timeout=20,                          # float → timeoutMilliseconds
    header_order=[...],                  # опционально; иначе порядок dict
)
s.headers.update({...})
s.cookies.set("name", "value", domain="example.com")

r = s.post(url, json={...}, headers={...}, header_order=[...], proxy=..., allow_redirects=True)
r.status_code, r.text, r.json(), r.headers, r.cookies, r.history, r.used_protocol, r.elapsed
```

Transport-опции (`force_http1`, `client_identifier`, `random_tls_extension_order`, `timeout`, `verify`,
`disable_http3`, `disable_session_tickets`, `server_name_overwrite`, `local_address`, ...) можно менять
между запросами как атрибуты — следующий запрос откроет новое соединение с новыми параметрами.
`s.reset_connection()` принудительно делает новый TLS-handshake.

### Кастомный отпечаток

```python
s = Session(
    ja3_string="771,4865-...,51764-27-65037-...,4588-29-23-24,0",
    # всё ниже опционально: незаданное берётся из Chrome 152, только если расширение есть в JA3
    supported_signature_algorithms=[...], key_share_curves=[...], supported_versions=[...],
    alpn_protocols=[...], alps_protocols=[...], cert_compression_algos=["brotli"],
    trust_anchors_payload="00b8...",      # для расширения 51764
    h2_settings={...}, h2_settings_order=[...], connection_flow=15663105,
    pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
    priority_frames=[...], header_priority={...},
    fill_custom_with_chrome_defaults=False,   # отключить автозаполнение
)
```

### Куки

`s.cookies` — `skeltahtls.CookieJar`: одна кука на **(name, domain, path)**, дубликатов нет ни в jar,
ни в отправляемом заголовке.

```python
s = Session(cookies=json.load(open("account.json")))   # browser-export как есть: domain, path, httpOnly, expirationDate...
s.cookies.load("a=1; b=2", domain=".example.com")      # строка Cookie-заголовка
s.cookies.update({"datadome": value})                  # без домена: перезаписывает существующую datadome, не плодит вторую
s.cookies.update({"datadome": value}, domain=".etsy.com")
s.cookies.set("x", "1", domain=".etsy.com", path="/", expires=..., secure=True, http_only=True, same_site="Lax")
s.cookies.get("datadome")            # значение самой специфичной; s.cookies["datadome"]
s.cookies.get_cookie("datadome")     # объект http.cookiejar.Cookie
s.cookies.remove("datadome", domain=".etsy.com"); s.cookies.clear_domain("etsy.com")
s.cookies.export()                   # список dict в формате browser-export (можно сохранить в account.json)
s.cookies.to_dict(domain="etsy.com") # {name: value}
```

Правила схлопывания: `etsy.com` ≡ `.etsy.com` (одна кука); `www.etsy.com` (host-only) — другая, но в запрос на
`www.etsy.com` уйдёт только она (самая специфичная), на `api.etsy.com` — `.etsy.com`. `Set-Cookie` с доменом
заменяет одноимённую «бездоменную» куку, поставленную через `update({...})`.

### Async

```python
async with AsyncSession() as s:
    rs = await asyncio.gather(*(s.get(u) for u in urls))
AsyncSession.configure_executor(128)   # размер общего пула потоков (по умолчанию 64)
```

## Обновление под новый Chrome

```bash
python scripts/build_binaries.py v1.17.0      # Go + zig; собирает из исходников тега для всех целей кроме macOS
python scripts/update_binaries.py 1.17.0 darwin   # macOS — из GitHub Releases (или build с MACOS_SDK=...)
python scripts/gen_profiles.py v1.17.0        # перегенерировать список идентификаторов, *_LATEST
pytest                                        # tests/test_fingerprint.py сверяет JA4/akamai с эталоном Chrome
```

Затем вручную сверить блок Chrome-дефолтов в `skeltahtls/profiles.py` с новым профилем в
`profiles/internal_browser_profiles.go` (sigalgs, key shares, trust_anchors payload) и обновить
эталонные хэши в `tests/test_fingerprint.py`.

Почему сборка из исходников: `cffi_dist/go.mod` в апстриме зафиксирован на *предыдущую* версию
tls-client, поэтому релизные бинарники отстают от тега (в DLL 1.16.0 нет имён `GREASE`/`MLDSA*`
для signature_algorithms → кастомный JA3 Chrome 150+ падает с «unknown ClientHelloID»).
`dependencies/manifest.json` хранит для каждого файла источник, sha256 и флаги `features`;
обёртка сама убирает неподдерживаемые имена, если работает на апстримном бинарнике (сейчас — macOS).

## Релиз

1. Поднять `__version__` в `skeltahtls/__version__.py` (схема `<tls-client>.<ревизия обёртки>`), закоммитить.
2. `git tag v1.16.0.3 && git push --tags` — [release.yml](.github/workflows/release.yml) соберёт wheel/sdist,
   опубликует на PyPI (trusted publishing, без токенов) и приложит файлы к GitHub Release.
3. Новые бинарники под свежий Chrome: Actions → *Build binaries* → тег bogdanfinn → появится ветка
   `binaries/<tag>` со всеми 8 файлами (macOS собирается нативно на runner-е) — открыть PR, прогнать
   `scripts/gen_profiles.py`, сверить Chrome-дефолты и эталонные хэши в тестах.

## Известные ограничения

- Заголовок `cookie` в HTTP/2 fhttp разбивает на отдельные поля на каждую куку (`cookie: a=1`, `cookie: b=2`),
  Chrome шлёт одно поле. Правится только в Go (fhttp `h2_bundle.go`); на серверной стороне после HPACK
  обычно неразличимо.
- `pseudo_header_order` со встроенным профилем изменить нельзя — только через `client_identifier=None` + `ja3_string`.
- `stream=True` из оригинальной обёртки убран (там был поток с временным файлом в cwd); тело всегда в памяти.
- macOS-бинарники — релизные апстримные (см. выше), собрать свои: `MACOS_SDK=... python scripts/build_binaries.py`.
