# npm-proxy

Захисний HTTP-проксі між клієнтом npm та офіційним registry, що в реальному часі аналізує кожен пакет, який встановлюється, і вирішує: пропустити, попередити чи заблокувати.

<img width="1747" height="1199" alt="Image" src="https://github.com/user-attachments/assets/47be1ddd-e55e-44f3-8823-dad2e17a1ff0" />

## Що робить аналізатор

Кожен запит на tarball (`GET /pkg/-/*.tgz`) проходить через 4-шаровий pipeline. Шари впорядковані за вартістю виконання - від дешевих перевірок метаданих до повного статичного аналізу коду - щоб відсіяти очевидно шкідливі пакети до дорогих етапів.

```
┌──────────────────────────────────────────────────────────────────┐
│  Layer 1 - метадані та зовнішні сигнали      (≈ 100–500 ms)     │
│  OSV │ typosquatting │ metadata │ anomaly │ license              │
│  → veto: OSV match → BLOCK 403                                   │
├──────────────────────────────────────────────────────────────────┤
│  Layer 2 - install-скрипти маніфесту         (≈ 10 ms)          │
│  regex-аналіз preinstall/install/postinstall/prepare             │
│  → veto: curl|sh, wget|sh → BLOCK 403                            │
├──────────────────────────────────────────────────────────────────┤
│  Layer 3 - статичний аналіз коду             (≈ 50–200 ms)      │
│  capabilities ∥ entropy → sinks → version_diff (script + deps)   │
│  → veto: sink + obfuscation → BLOCK 403                          │
├──────────────────────────────────────────────────────────────────┤
│  Layer 4 - policy engine                                         │
│  R(p) = ∑ score, cap 1.0; пороги 0.30 (warn) / 0.70 (block)      │
│  → BLOCK 403 │ ALLOW + X-Security-Warning │ ALLOW 200            │
└──────────────────────────────────────────────────────────────────┘
                                  │
                  ┌───────────────┼───────────────┐
              SHA-256          SIEM emit      Background
              verdict cache    (syslog/        recheck worker
              (Redis, 24h)     webhook)        (warn → block)
```

### Детектори

| Шар | Файл | Rule | Score | Veto | CWE | Що виявляє |
|-----|------|------|-------|------|-----|------------|
| 1 | [layer1/osv.go](internal/analyzer/layer1/osv.go) | `osv_known_vulnerability` | 1.0 | так | CWE-1035 | відомі вразливості з OSV.dev |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_levenshtein` | 0.40 | ні | CWE-1035 | імена близькі до top-10k за Damerau-Levenshtein |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_ascii_homoglyph` | 0.50 | ні | CWE-1035 | заміна цифр/символів у назві (`react0`, `l0dash`) |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_new_package` | 0.20 | ні | - | пакет опублікований менше N днів тому |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_young_maintainer` | 0.25 | ні | - | обліковий запис мейнтейнера молодший N днів |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_low_downloads` | 0.15 | ні | - | менше порогових завантажень на місяць |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_popular_but_stale` | 0.10 | ні | - | популярний пакет без оновлень понад N днів |
| 1 | [layer1/anomaly.go](internal/analyzer/layer1/anomaly.go) | `anomaly_release_burst` | 0.20 | ні | - | кілька версій у короткий проміжок часу |
| 1 | [layer1/anomaly.go](internal/analyzer/layer1/anomaly.go) | `anomaly_maintainer_change` | 0.30 | ні | - | мейнтейнер змінився після попереднього релізу |
| 1 | [layer1/anomaly.go](internal/analyzer/layer1/anomaly.go) | `anomaly_unusual_publish_hour` | 0.10 | ні | - | публікація поза звичним вікном активності |
| 1 | [layer1/anomaly.go](internal/analyzer/layer1/anomaly.go) | `anomaly_size_spike` | 0.15 | ні | - | розмір tarball аномально більший за попередні |
| 1 | [layer1/license.go](internal/analyzer/layer1/license.go) | `license_missing` | 0.10 | ні | - | поле `license` відсутнє або порожнє |
| 1 | [layer1/license.go](internal/analyzer/layer1/license.go) | `license_changed_in_patch` | 0.25 | ні | - | ліцензія змінилась у patch-релізі |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_curl_sh` | 1.0 | так | CWE-78 | `curl\|sh` / `wget\|sh` - pipe-виконання скрипта з мережі |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_base64` | 0.35 | ні | CWE-506 | `base64 -d` або `atob` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_child_process` | 0.20 | ні | CWE-78 | `require('child_process')` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_eval` | 0.15 | ні | CWE-95 | `eval(...)` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_node_eval` | 0.15 | ні | CWE-95 | `node -e "..."` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_dynamic_require` | 0.10 | ні | CWE-706 | `require(variable)` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_external_url` | 0.08 | ні | CWE-829 | http/https-посилання у lifecycle-скрипті |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `cap_exec` | 0.15 | ні | CWE-78 | `child_process.exec/spawn` у коді |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `cap_net` | 0.30 | ні | CWE-918 | мережеві виклики (`http`, `https`, `net`) |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `cap_fs_sensitive` | 0.25 | ні | CWE-732 | доступ до чутливих шляхів (`/etc/passwd`, `~/.ssh`) |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `cap_dynamic_eval` | 0.20 | ні | CWE-95 | `eval`, `new Function`, `vm.runIn*` |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `cap_env_read` | 0.10 | ні | CWE-200 | читання змінних оточення (`process.env`) |
| 3 | [layer3/entropy.go](internal/analyzer/layer3/entropy.go) | `entropy_obfuscation` | 0.30 | ні | CWE-506 | Shannon entropy > порогу або base64/hex ratio |
| 3 | [layer3/sinks.go](internal/analyzer/layer3/sinks.go) | `sink_eval` / `sink_new_function` / `sink_vm_run` / `sink_dynamic_require` | 0.20 | ні | CWE-95 | небезпечні sink-функції без ознак обфускації |
| 3 | [layer3/sinks.go](internal/analyzer/layer3/sinks.go) | (той самий rule) | - | так | CWE-95 | sink + обфускація - veto |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_exec_in_patch` | 0.35 | ні | CWE-78 | поява `child_process` у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_net_in_patch` | 0.25 | ні | CWE-918 | поява мережевих викликів у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_deps_in_patch` | 0.20 | ні | CWE-829 | нові `dependencies` у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_script_in_patch` | 0.30 | ні | CWE-506 | поява lifecycle-скрипту у patch-релізі |
| 4 | [policy/engine.go](internal/policy/engine.go) | - | - | - | - | агрегує сигнали, застосовує veto та пороги |

Усі ваги налаштовуються через [configs/proxy.yaml](configs/proxy.yaml) без перекомпіляції.

### Формула ризику

```
         ⎧ 1,                     якщо ∃ s ∈ S(p) : s.veto = true
R(p) = ⎨
         ⎩ min(1, Σ s.score),    інакше

verdict = BLOCK  якщо R ≥ 0.70  або veto
        = WARN   якщо 0.30 ≤ R < 0.70   (HTTP 200 + X-Security-Warning)
        = ALLOW  якщо R < 0.30
```

### Post-factum перевірки

Фоновий worker ([internal/recheck/](internal/recheck/)) кожні N годин переаналізує warn-вердикти з кешу: якщо OSV або typosquat-list оновилися, пакет з warn може ретроспективно стати block. Подія `retroactive_block` емітиться в SIEM окремим типом.

## Запуск

```bash
# 1. Згенерувати top-10k список популярних пакетів (одноразово або при оновленні)
go run ./cmd/gen-top10k -out configs/top10k.txt -target 10000

# 2. Запустити всі сервіси (проксі + Redis)
docker compose -f deployments/docker-compose.yml up -d

# 3. Налаштувати npm на проксі
npm config set registry http://localhost:8080
```

## Структура проекту

```
cmd/
├─ proxy/              HTTP-сервер, точка входу
└─ gen-top10k/         генератор популярних npm-пакетів через search API

internal/
├─ analyzer/
│  ├─ engine.go        оркестратор Layer 2 + 3 (post-download)
│  ├─ layer1/          метадані та зовнішні сигнали
│  ├─ layer2/          install scripts
│  └─ layer3/          статичний аналіз: capabilities, entropy, sinks, version diff
├─ policy/             агрегація сигналів + thresholds
├─ recheck/            фоновий post-factum worker
├─ signal/             типи Signal/Result
├─ proxy/              HTTP handler
├─ registry/           клієнт npm registry + downloads + user API
├─ cache/              Redis verdict + OSV cache
├─ extractor/          in-memory розпаковка tarball
├─ integrity/          SHA-256/512 verification
├─ siem/               syslog (RFC-5424) + webhook (HMAC) emitter
└─ config/             YAML config + env override через koanf

configs/
├─ proxy.yaml          усі ваги, пороги, таймаути
└─ top10k.txt          10k популярних пакетів за weekly downloads

test/
└─ fixtures/           5 пакетів-зразків: clean, malicious-install, typosquat,
                       new-exec-in-patch, obfuscated-eval

docs/                 
├─ analyzer-flow.puml  UML activity diagram
├─ detectors-table.md  зведена характеристика методів
└─ risk-formula.md     формула ризику + приклади розрахунку
```

## Спостережуваність

- Кожен вердикт емітиться як `package_verdict` подія з повним переліком rules та CWE
- Підтримка syslog RFC-5424 (TCP/UDP) та webhook (HMAC-SHA256)
- Async-буфер 256 подій, fallback на stderr якщо SIEM недоступний
- Конфіг - секція `siem` у proxy.yaml

## Технологічний стек

- **Go 1.25**
- **esbuild** - валідація JS/TS синтаксису
- **Redis** - кеш вердиктів (24 год TTL) та кеш OSV-результатів
- **OSV.dev API** - база відомих вразливостей
- **npm registry & downloads API** - метадані пакетів і статистика завантажень
- **koanf** - YAML config з override через змінні оточення
- **golang.org/x/text/unicode/norm** - NFKC-нормалізація для typosquatting
- **Masterminds/semver/v3** - парсинг версій з pre-release/build метаданими

## Тестування

```bash
go test ./...                   # unit + integration
go test ./test/integration/...  # тільки end-to-end перевірка pipeline (Layer 2 → Layer 3 → policy engine)
```

### Ручне тестування через npm

Спрямувати npm на локальний проксі та поставити пакет як зазвичай:

```bash
# 1. Підняти проксі + Redis + syslog-ng
docker compose -f deployments/docker-compose.yml up -d

# 2. Направити npm на проксі
npm config set registry http://localhost:8080

# 3. Підготувати пісочницю та скинути кеші
mkdir npm-test && cd npm-test && npm init -y
npm cache clean --force
docker compose -f ../deployments/docker-compose.yml exec redis redis-cli FLUSHDB

# 4. Тестові сценарії
npm install lodash@4.17.21       # OSV-вето → E403 (3 GHSA: prototype pollution + code injection)
npm install ua-parser-js@0.7.29  # OSV-вето → E403 (компрометація 2021)
npm install express              # ALLOW або WARN (200 OK)

# 5. Стежити за вердиктами в SIEM
docker compose -f deployments/docker-compose.yml exec syslog-ng tail -f /var/log/syslog-ng/npm-proxy.log

# 6. Повернутися на офіційний registry
npm config delete registry
```

Аналіз спрацьовує тільки на запит tarball (`GET /<pkg>/-/<pkg>-<ver>.tgz`); запити метаданих проходять reverse-проксі без аналізу.

## Обмеження та future work

- Аналіз коду виконується regex-патернами з валідацією синтаксису через esbuild - повний AST walk залишений як future work
- Динамічний аналіз (sandbox-виконання install-скриптів) не реалізовано
- BK-tree індексація top-10k не реалізована - наразі лінійне сканування з length-pruning, прийнятне в межах 500 ms бюджету Layer 1
- Top-10k список оновлюється вручну запуском `cmd/gen-top10k` можливо можна буде автоматизувати 
- Більш точне калібрування параметрів у proxy.yaml
- Спробувати імплементувати ШІ
