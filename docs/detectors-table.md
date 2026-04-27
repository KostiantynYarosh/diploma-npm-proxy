# Детектори - зведена таблиця

| Шар | Детектор | Rule | Score | Veto | CWE | Що виявляє |
|-----|----------|------|-------|------|-----|------------|
| 1 | OSV | `osv_known_vulnerability` | 1.0 | так | CWE-1035 | відомі вразливості з OSV.dev |
| 1 | Typosquatting (Levenshtein) | `typosquat_levenshtein` | 0.40 | ні | CWE-1035 | імена близькі до top-10k за Damerau-Levenshtein |
| 1 | Typosquatting (ASCII homoglyph) | `typosquat_ascii_homoglyph` | 0.50 | ні | CWE-1035 | заміна цифр/символів у назві (`react0`, `l0dash`) |
| 1 | Metadata - новий пакет | `metadata_new_package` | 0.20 | ні | - | пакет опублікований < N днів тому |
| 1 | Metadata - молодий мейнтейнер | `metadata_young_maintainer` | 0.25 | ні | - | обліковий запис мейнтейнера молодший N днів |
| 1 | Metadata - низькі завантаження | `metadata_low_downloads` | 0.15 | ні | - | менше порогових завантажень на місяць |
| 1 | Metadata - popular-but-stale | `metadata_popular_but_stale` | 0.10 | ні | - | популярний пакет без оновлень понад N днів |
| 1 | Anomaly - сплеск релізів | `anomaly_release_burst` | 0.20 | ні | - | кілька версій в короткий проміжок часу |
| 1 | Anomaly - зміна мейнтейнера | `anomaly_maintainer_change` | 0.30 | ні | - | мейнтейнер змінився після попереднього релізу |
| 1 | Anomaly - нетипова година | `anomaly_unusual_publish_hour` | 0.10 | ні | - | публікація поза звичним вікном активності |
| 1 | Anomaly - відхилення розміру | `anomaly_size_spike` | 0.15 | ні | - | розмір tarball аномально більший за попередні |
| 1 | License - відсутня | `license_missing` | 0.10 | ні | - | поле `license` відсутнє або порожнє |
| 1 | License - зміна у patch | `license_changed_in_patch` | 0.25 | ні | - | ліцензія змінилась у patch-релізі |
| 2 | Install scripts - curl\|sh / wget\|sh | `install_script_curl_sh` | 1.0 | так | CWE-78 | небезпечне pipe-виконання скрипта з мережі |
| 2 | Install scripts - base64 decode | `install_script_base64` | 0.35 | ні | CWE-506 | `base64 -d` або `atob` у скрипті встановлення |
| 2 | Install scripts - child_process | `install_script_child_process` | 0.20 | ні | CWE-78 | `require('child_process')` у lifecycle-скрипті |
| 2 | Install scripts - eval | `install_script_eval` | 0.15 | ні | CWE-95 | `eval(...)` у lifecycle-скрипті |
| 2 | Install scripts - node -e | `install_script_node_eval` | 0.15 | ні | CWE-95 | `node -e "..."` у lifecycle-скрипті |
| 2 | Install scripts - dynamic require | `install_script_dynamic_require` | 0.10 | ні | CWE-706 | `require(variable)` у lifecycle-скрипті |
| 2 | Install scripts - external URL | `install_script_external_url` | 0.08 | ні | CWE-829 | http/https посилання у lifecycle-скрипті |
| 3 | Capabilities - exec | `cap_exec` | 0.15 | ні | CWE-78 | `child_process.exec/spawn` у коді |
| 3 | Capabilities - net | `cap_net` | 0.30 | ні | CWE-918 | мережеві виклики (`http`, `https`, `net`) |
| 3 | Capabilities - fs-sensitive | `cap_fs_sensitive` | 0.25 | ні | CWE-732 | доступ до чутливих шляхів (`/etc/passwd`, `~/.ssh`) |
| 3 | Capabilities - dynamic eval | `cap_dynamic_eval` | 0.20 | ні | CWE-95 | `eval`, `new Function`, `vm.runIn*` |
| 3 | Capabilities - env read | `cap_env_read` | 0.10 | ні | CWE-200 | читання змінних оточення (`process.env`) |
| 3 | Entropy - обфускація | `entropy_obfuscation` | 0.30 | ні | CWE-506 | Shannon entropy > порогу або base64/hex ratio |
| 3 | Sinks - без обфускації | `sink_eval` / `sink_new_function` / `sink_vm_run` / `sink_dynamic_require` | 0.20 | ні | CWE-95 | небезпечні sink-функції без ознак обфускації |
| 3 | Sinks + обфускація | (той самий rule) | - | так | CWE-95 | sink-функція в поєднанні з обфускацією |
| 3 | Version diff - новий exec у patch | `version_diff_new_exec_in_patch` | 0.35 | ні | CWE-78 | поява `child_process` у patch-релізі |
| 3 | Version diff - новий net у patch | `version_diff_new_net_in_patch` | 0.25 | ні | CWE-918 | поява мережевих викликів у patch-релізі |
| 3 | Version diff - нові залежності у patch | `version_diff_new_deps_in_patch` | 0.20 | ні | CWE-829 | нові `dependencies` у patch-релізі |
| 3 | Version diff - новий скрипт у patch | `version_diff_new_script_in_patch` | 0.30 | ні | CWE-506 | поява lifecycle-скрипту у patch-релізі |

## Примітки

- **Veto** - якщо хоча б один сигнал має `veto=true`, підсумковий вердикт завжди `BLOCK` незалежно від суми балів.
- **Score** - внесок сигналу до формули `R(p) = min(1, Σ score)`. Пороги: `0.30` (WARN) / `0.70` (BLOCK).
- Усі ваги налаштовуються через [configs/proxy.yaml](../configs/proxy.yaml) без перекомпіляції.
