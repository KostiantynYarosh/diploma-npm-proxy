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
│  capabilities ∥ entropy → sinks → version_diff → combo signals   │
│  → scored: sink+obfuscation / install+exec / install+obfuscation │
├──────────────────────────────────────────────────────────────────┤
│  Layer 4 - policy engine                                         │
│  R(p) = ∑ score, cap 1.0; warn/block thresholds + warn gate      │
│  → BLOCK 403 │ ALLOW + X-Security-Warning │ ALLOW 200            │
└──────────────────────────────────────────────────────────────────┘
                                  │
                  ┌───────────────┼───────────────┐
              SHA-256          SIEM emit      Background
              verdict cache    (syslog/        recheck worker
              (Redis, 24h)     webhook)        (warn → block)
```

### Детектори

| Шар | Файл | Rule | Veto | CWE | Що виявляє |
|-----|------|------|------|-----|------------|
| 1 | [layer1/osv.go](internal/analyzer/layer1/osv.go) | `osv_known_vulnerability` | так | CWE-1035 | відомі вразливості з OSV.dev |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_close` / `typosquat_warn` | ні | CWE-1035 | імена близькі до top-10k; BK-tree (Levenshtein, ≤ warn_distance) → Damerau-Levenshtein refinement (close = відстань 1, warn = відстань 2) |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_ascii_homoglyph` | ні | CWE-1035 | заміна цифр/символів у назві (`react0`, `l0dash`) |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_combosquat` | ні | CWE-1035 | популярний пакет як сегмент складеного імені (`react-fake`, `axios-utils`, `eth-keycontroler`) — ловить combosquat, до якого edit-distance сліпий |
| 1 | [layer1/typosquatting.go](internal/analyzer/layer1/typosquatting.go) | `typosquat_scope_close` / `typosquat_scope_warn` | ні | CWE-1035 | scope близький до популярного scope (`@bavel` vs `@babel`, `@typess` vs `@types`); список scopes дериватив з top10k |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_new_package` | ні | - | пакет опублікований менше N днів тому |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_young_maintainer` | ні | - | обліковий запис мейнтейнера молодший N днів |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_single_maintainer` | ні | - | пакет має лише одного мейнтейнера |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_low_downloads` | ні | - | менше порогових завантажень на місяць |
| 1 | [layer1/metadata.go](internal/analyzer/layer1/metadata.go) | `metadata_popular_but_stale` | ні | - | популярний пакет без оновлень понад N днів |
| 1 | [layer1/anomaly.go](internal/analyzer/layer1/anomaly.go) | `anomaly_version_spike` | ні | - | кілька версій у короткий проміжок часу |
| 1 | [layer1/license.go](internal/analyzer/layer1/license.go) | `license_patch_change` | ні | - | ліцензія змінилась у patch-релізі |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_present_<hook>` | ні | CWE-506 | будь-який непорожній lifecycle-скрипт (preinstall/install/postinstall/prepare) |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_curl_pipe_<hook>` / `install_script_wget_pipe_<hook>` | так | CWE-506 | `curl\|sh` / `wget\|sh` - pipe-виконання скрипта з мережі |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_base64_decode_<hook>` | ні | CWE-506 | `base64 -d` або `atob` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_child_process_<hook>` | ні | CWE-506 | `require('child_process')` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_eval_<hook>` | ні | CWE-506 | `eval(...)` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_node_eval_<hook>` | ні | CWE-506 | `node -e "..."` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_dynamic_require_<hook>` | ні | CWE-506 | `require(variable)` у lifecycle-скрипті |
| 2 | [layer2/install_scripts.go](internal/analyzer/layer2/install_scripts.go) | `install_script_external_url_<hook>` | ні | CWE-506 | http/https-посилання у lifecycle-скрипті |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `capability_exec` | ні | CWE-78 | `child_process.exec/spawn` у коді |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `capability_dynamic_eval` | ні | CWE-94 | `eval`, `new Function`, `vm.runIn*` |
| 3 | [layer3/capabilities.go](internal/analyzer/layer3/capabilities.go) | `capability_env_read` | ні | - | читання змінних оточення (`process.env`) |
| 3 | [layer3/entropy.go](internal/analyzer/layer3/entropy.go) | `obfuscation_high_entropy` | ні | CWE-506 | Shannon entropy > порогу або base64/hex ratio |
| 3 | [layer3/sinks.go](internal/analyzer/layer3/sinks.go) | `sink_eval` / `sink_new_function` / `sink_vm_run_this_context` / `sink_vm_run_new_context` / `sink_dynamic_require` | ні | CWE-95 | небезпечні sink-функції без ознак обфускації |
| 3 | [layer3/sinks.go](internal/analyzer/layer3/sinks.go) | `sink_with_obfuscation` | ні | CWE-95 | sink + висока ентропія в одному пакеті (важче за sink_alone, але не veto - мініфіковані bundle-и легально матчать патерн) |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_exec_in_patch` | ні | CWE-78 | поява `child_process` у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_net_in_patch` | ні | CWE-918 | поява мережевих викликів у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_dependency` | ні | CWE-829 | нові `dependencies` у patch-релізі |
| 3 | [layer3/version_diff.go](internal/analyzer/layer3/version_diff.go) | `version_diff_new_script_<hook>` / `version_diff_changed_script_<hook>` | ні | CWE-506 | поява або зміна lifecycle-скрипту у patch-релізі |
| 3 | [combo.go](internal/analyzer/combo.go) | `typosquat_with_install_script` | ні | CWE-506 | typo/homoglyph + lifecycle-скрипт; сильніший сигнал, ніж сума окремих слабких правил |
| 3 | [combo.go](internal/analyzer/combo.go) | `install_script_with_exec` | ні | CWE-78 | lifecycle-скрипт + exec/child_process у коді або самому install hook |
| 3 | [combo.go](internal/analyzer/combo.go) | `install_script_with_network` | ні | CWE-829 | lifecycle-скрипт + мережевий доступ або external URL |
| 3 | [combo.go](internal/analyzer/combo.go) | `install_script_with_obfuscation` | ні | CWE-506 | lifecycle-скрипт + entropy/sink_with_obfuscation; ловить тихі install-carrier пакети |
| 4 | [policy/engine.go](internal/policy/engine.go) | - | - | - | агрегує сигнали, застосовує veto та пороги |

Score-ваги в таблиці навмисно опущені: вони не є константами, а підбираються офлайн-калібратором (див. секцію «Калібрація ваг») під жорсткі cap-и на benign-block / benign-warn rate і записуються в [configs/proxy.yaml](configs/proxy.yaml) - тому будь-яке конкретне число тут одразу б розходилось з конфігом після наступного прогону. Veto-сигнали (`osv_known_vulnerability`, `install_script_curl_pipe_*`, `install_script_wget_pipe_*`) калібрації не підлягають - вони завжди дають вердикт BLOCK незалежно від ваг.

Кілька раніше задуманих правил було вилучено після того, як калібратор стабільно занулював їхні ваги на кількох операційних профілях через надмірний внесок у FP-бюджет: `anomaly_maintainer_change`, `anomaly_unusual_publish_hour`, `anomaly_size_deviation`, `license_missing`, `capability_net_access` (як окремий сигнал; детекція CapNet збережена для `version_diff_new_net_in_patch`), `capability_fs_sensitive`. Це не означає що сигнали безкорисні в принципі - на ширшому корпусі з реальною плинністю мейнтейнерів і явним базовим розподілом publish-hour вони можуть повернутись.

### Формула ризику

```
         ⎧ 1,                     якщо ∃ s ∈ S(p) : s.veto = true
R(p) = ⎨
         ⎩ min(1, Σ s.score),    інакше

categories(p) = unique({category(rule) | rule ∈ triggered(p)})

verdict = BLOCK  якщо veto або R ≥ block_threshold
        = WARN   якщо allow_threshold ≤ R < block_threshold і |categories(p)| ≥ min_categories
        = ALLOW  інакше
```

**Multi-category gating** (`policy.min_categories`, default 2): застосовується лише до warn-смуги. Якщо score вже перетнув `block_threshold`, пакет блокується без category gate; якщо score між `allow_threshold` і `block_threshold`, потрібні правила з ≥N незалежних категорій (metadata, capability, install, sink, entropy, anomaly, license, version_diff, typosquat, combo). Це усуває alarm-fatigue від поодинокого шумного правила, але не дає gate випадково пропустити очевидний block. Veto-сигнали (curl|sh, OSV) теж обходять gating.

### Post-factum перевірки

Фоновий worker ([internal/recheck/](internal/recheck/)) кожні N годин переаналізує warn-вердикти з кешу: якщо OSV або typosquat-list оновилися, пакет з warn може ретроспективно стати block. Подія `retroactive_block` емітиться в SIEM окремим типом.

## Запуск

```bash
# 1. Згенерувати top-10k список популярних пакетів (опційно; import-benign зробить це сам, якщо файла немає)
go run ./tools/gen-top10k -out configs/top10k.txt -target 10000

# 2. Запустити всі сервіси (проксі + Redis)
docker compose -f deployments/docker-compose.yml up -d

# 3. Налаштувати npm на проксі
npm config set registry http://localhost:8080
```

## Структура проекту

```
cmd/
└─ proxy/              HTTP-сервер, точка входу

internal/
├─ analyzer/
│  ├─ engine.go        оркестратор Layer 2 + 3 (post-download)
│  ├─ combo.go         cross-layer combination signals
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
├─ semverutil/         спільні хелпери для semver-парсингу
├─ calibrate/          ядро калібратора: метрики, кешування сигналів, search loop, reports
└─ config/             YAML config + env override через koanf

tools/
├─ gen-top10k/         генератор популярних npm-пакетів через search API
├─ import-benign/      імпорт benign corpus з top10k.txt
├─ import-datadog/     імпорт DataDog malicious corpus
└─ calibrate/          CLI офлайн-калібратора ваг і policy-порогів

configs/
├─ proxy.yaml          усі ваги, пороги, таймаути
└─ top10k.txt          10k популярних пакетів за weekly downloads

test/
├─ fixtures/           5 пакетів-зразків: clean-package, malicious-install-script,
│                      typosquat-lodash, new-exec-in-patch, obfuscated-eval
└─ integration/        end-to-end перевірка pipeline (Layer 2 → Layer 3 → policy)

docs/
└─ detectors-table.md  зведена характеристика методів
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

## Калібрація ваг

Замість підбирати score-ваги в [configs/proxy.yaml](configs/proxy.yaml) на око, є офлайн-калібратор який оптимізує катч-рейт малварі під жорстким cap-ом на benign-block rate (false-positive контроль).

```
tools/import-benign    # тягне топ-N benign пакетів з configs/top10k.txt для FP-тестування
tools/import-datadog   # імпортує password-protected zip-и з DataDog malicious-software-packages-dataset
tools/calibrate        # проганяє pipeline паралельно, шукає ваги/пороги/min_categories
internal/calibrate     # ядро: метрики (2×3 матриця), кешування сигналів, search loop, reports
```

### 1. Зібрати корпус

Корпус двочастинний:
- **`dataset/benign/`** - топ-N популярних npm-пакетів, для виміру false-positive rate.
- **`dataset/malicious/`** - реальна малварь з DataDog dataset.

```bash
# Negative class (FP-тестування)
go run ./tools/import-benign -top 10000 -concurrency 3
```

`import-benign` читає список з `configs/top10k.txt`. Якщо файла немає або в ньому менше пакетів, ніж просить `-top`, тул сам запускає `tools/gen-top10k` і генерує список перед імпортом. На `429`/`5xx` від npm registry є retry/backoff; якщо registry все одно душить запити, зменши `-concurrency` до 1.

Після завершення `dataset/benign/` має `<name>@<version>.tgz`, `<name>.meta.json`, `labels.jsonl` (категорія `popular`). `labels.jsonl` - це manifest корпусу, а не ручний список: він фіксує `name`, `version`, шляхи до tarball/meta, `category`, OSV/prev_version для malicious-зразків і робить калібрацію відтворюваною. Калібратор читає саме manifest, а не просто всі `.tgz` у директорії.

#### Додати справжню малварь з DataDog dataset

[DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) постійно оновлюється, чітко поділяє `compromised_lib` (зламані легітимні пакети) і `malicious_intent` (троянські з нуля), кожен зразок у password-protected zip (`infected`).

```bash
# 1. Клонувати репо (sparse checkout npm-частини, щоб не качати pypi/ai-skills)
git clone --filter=blob:none --no-checkout https://github.com/DataDog/malicious-software-packages-dataset.git
cd malicious-software-packages-dataset
git sparse-checkout init --cone
git sparse-checkout set samples/npm
git checkout main
cd ..

# 2. Імпортувати - тул дешифрує zip-и, розпаковує/перепаковує в npm-tarball,
#    хешує для дедуплу і дописує в dataset/malicious/labels.jsonl з відповідною
#    категорією (compromised_lib | malicious_intent).
go run ./tools/import-datadog -src ./malicious-software-packages-dataset
```

Запускай лише в ізольованому середовищі - навіть без виконання, наявність активної малварі на диску може тригерити антивіруси. Тул не запускає жоден файл; лише декомпресує і пише `.tgz` на диск.

### 2. Запустити калібрацію

```bash
go run ./tools/calibrate -workers 16 -trials 3000 -max-hard-fp 0.001 -max-soft-fp 0.05
```

Шляхи до конфігу/корпусу/звіту фіксовані (`configs/proxy.yaml` → `configs/proxy.calibrated.yaml` + `calibration-report.csv`, корпус у `dataset/`). Зміна паттерну - у константах [tools/calibrate/main.go](tools/calibrate/main.go).

Два жорсткі cap-и:
- **`-max-hard-fp`** - стеля benign-block rate. False-block = непрацюючий `npm install`, тому production-профіль тримає її біля нуля (`0.001` або жорсткіше).
- **`-max-soft-fp`** - стеля benign-warn rate. Якщо warn з'являється на багатьох популярних пакетах, розробники привчаються його ігнорувати (alarm fatigue) - warn-канал стає шумом. Для маленького benign validation `0.03`/`0.05` відрізняються буквально кількома пакетами.

Основні knobs:
- **`-workers`** - кількість паралельних pipeline worker-ів для аналізу корпусу; за замовчуванням `runtime.NumCPU()`.
- **`-trials`** - budget random search для кожного кандидата `min_categories`.
- **`-min-categories`** - список значень для tuning policy gate; default `1,2,3`, тому зазвичай прапор не треба вказувати.
- **`-strip-osv`** - прибирає OSV veto з cached runs, щоб калібрувати scored-сигнали без домінування відомих CVE.

Під обома стелями пошук максимізує **catch** = частку малварних пакетів, які потрапили хоча б у `warn`. Звіт включає `warn_precision` (P[malicious | warn]) - діагностика дискримінативної сили warn-вердикту: < 0.95 = warn-канал слабкий, треба покращувати детектори.

Калібратор:
1. Проганяє pipeline один раз на пакет паралельними worker-ами, кешує `(rule, score, veto)` сигнали
2. Phase A - random search над tunable score-вагами, `allow_threshold`, `block_threshold` і `min_categories`
3. Phase B - coordinate descent зі step=0.05 на найкращому random-кандидаті кожної `min_categories`-гілки
4. Пише `proxy.calibrated.yaml` (готовий до підстановки) + `calibration-report.csv` з усіма trials
5. Друкує Pareto frontier, per-category breakdown, top malicious misses, benign FP tables і фінальний summary

Фінальний summary наприкінці логу прив'язаний саме до вибраного best validation trial:

```
final statistics (selected best validation trial):
  selected_trial=... objective_score=... metrics=catch=... block=... hard_fp=... soft_fp=...
  config: allow=... block=... min_categories=... feasible=...
  catch=...      # malicious warn+block
  warn=...       # malicious warn
  block=...      # malicious block verdict
  miss=...       # malicious allow
  warn_fp=...    # benign warn
  block_fp=...   # benign block
```

### 3. Перевірити результат

```bash
# Регресія fixture-test'ів - мають проходити з новими вагами
go test ./test/integration/...

# Eval на тому самому корпусі для baseline-порівняння
go run ./tools/calibrate -eval-only

# Підставити калібрований конфіг у Docker
docker compose -f deployments/docker-compose.yml down
cp configs/proxy.calibrated.yaml configs/proxy.yaml
docker compose -f deployments/docker-compose.yml up -d --build
```

### Обмеження калібратора

- **Network-залежні Layer 1 сигнали вимкнені** (downloads, maintainer-age) - у корпусі немає їх snapshot-ів. Ваги цих rules лишаються 0 і не впливають на пошук. Щоб увімкнути - розширити import tools snapshot-ами цих API і полями в `labels.jsonl`.
- **OSV-вето домінує над scored-сигналами** - якщо більшість malicious у корпусі мають OSV-match, інші детектори майже не калібруються. Запусти калібрацію з `-strip-osv` щоб побачити чесну картину сигнатурного стеку. Для layer 2/3 найцінніші `malicious_intent` зразки без OSV-відомості.
- **Per-category breakdown** - `calibrate` друкує метрики окремо для `compromised_lib`, `malicious_intent`, `popular`, `(uncategorised)`. Якщо `malicious_intent` catch сильно нижчий - це реальна діра в евристиках, а не проблема OSV.
- **Розмір benign-сплиту впливає на статистичну точність FP** - на ~2k benign у val один помилковий warn = ~0.05% soft_fp; для жорстких порівнянь профілів варто тримати ≥5k benign і явно вказувати observed-FP як «N з M» поряд з відсотком. Особливо важливо включати CLI/native/build/devtool пакети з install scripts, бо саме вони — головне джерело реальних false-positive.
- **Class imbalance** - у проді частка malicious << 1%, наш ~50/50 split дає оптимістичну precision. Інтерпретуй метрики з поправкою на prior.

## Обмеження та future work

- Аналіз коду виконується regex-патернами з валідацією синтаксису через esbuild - повний AST walk залишений як future work
- Динамічний аналіз (sandbox-виконання install-скриптів) не реалізовано
- Typosquat-пошук імплементовано через BK-tree на Levenshtein з рефайнментом Damerau-Levenshtein — O(log N) lookup, дозволяє розширення top-N без CPU-впливу
- Top-10k список може генеруватись вручну через `tools/gen-top10k`; `tools/import-benign` автоматично запускає генерацію, якщо `configs/top10k.txt` відсутній або замалий
- Калібратор ваг є (див. секцію «Калібрація ваг»), benign/DataDog імпорт автоматизований; варто додати імпорт з Backstabber's Knife Collection або MalOSS для ширшого malicious corpus з типологією
- Network-залежні Layer 1 сигнали (downloads, maintainer-age) у калібраторі вимкнені - потрібен snapshot цих API в датасеті
- Спробувати імплементувати ШІ
