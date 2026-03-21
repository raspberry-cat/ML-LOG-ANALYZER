# log-anomaly-detector

Сервис для поиска аномалий в access-логах Nginx с объяснением через правила MITRE ATT&CK.

Проект рассчитан на два режима работы:
- приём пакетов логов через REST API;
- чтение указанных файлов логов при старте приложения через `.env`.

## Что делает сервис

- разбирает JSONL и обычный текстовый access-log Nginx;
- приводит поля журнала к единой модели через `.env`;
- извлекает 26 числовых признаков из каждого HTTP-запроса;
- определяет аномалии через `Isolation Forest` или частотный baseline;
- дополняет найденные аномалии техниками MITRE ATT&CK;
- хранит последние аномалии и агрегаты в памяти;
- отдаёт REST API, JSON-метрики и Prometheus `/metrics`.

## Структура проекта

```text
api/                FastAPI и HTTP-эндпоинты
core/               модели, нормализация, логирование, настройки
services/           парсер, признаки, ingest, MITRE, обучение, основной сервис
detectors/          baseline, Isolation Forest, реестр артефактов модели
scripts/            обучение, валидация, генерация и вспомогательные утилиты
tests/              тесты
grafana/            дашборд и provisioning
prometheus/         конфиг Prometheus
docs/               схемы и вспомогательные материалы
```

Каталоги `data/` и `artifacts/` используются локально и не входят в публичную версию репозитория.
Обучающие и валидационные наборы логов, а также готовые артефакты модели нужно подготовить отдельно.

## Требования

- Python 3.14+
- Docker и Docker Compose для контейнерного запуска

Внешняя база данных не нужна.

## Локальный запуск

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Обучение

Обычное обучение на своём наборе логов:

```bash
python scripts/train.py \
    --input /path/to/train.jsonl \
    --model isolation_forest
```

Потоковое обучение на большом файле:

```bash
python scripts/train_large.py \
    --input /path/to/large-train.jsonl
```

Валидация:

```bash
python scripts/validate_model.py \
    --input /path/to/validation.jsonl
```

Для локального быстрого прогона можно сначала сгенерировать синтетические логи:

```bash
python scripts/generate_logs.py --total 5000 --anomaly-ratio 0.05
```

## Запуск приложения

```bash
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### Режим 1. Приём логов через API

- `GET /health` — состояние сервиса и базовая конфигурация
- `POST /ingest` — загрузка массива строк журнала в поле `lines`
- `GET /anomalies` — последние аномалии
- `GET /metrics` — Prometheus exposition format
- `GET /metrics/json` — агрегаты из памяти

Пример запроса:

```bash
curl -X POST http://localhost:8000/ingest \
  -H 'Content-Type: application/json' \
  -d '{"lines":["{\"timestamp\":\"2026-03-10T14:00:00+00:00\",\"remote_addr\":\"10.0.0.1\",\"method\":\"GET\",\"path\":\"/index.html\",\"status\":200}"]}'
```

### Режим 2. Чтение файлов логов через `.env`

Если нужно, чтобы сервис сам прочитал файлы при старте, задайте:

```dotenv
AUTO_INGEST_LOG_FILES_ON_STARTUP=true
LOG_INPUT_PATHS=["./data/logs/input.jsonl"]
```

Сервис читает файлы пакетами по `INGEST_BATCH_SIZE`, прогоняет их через тот же конвейер и сразу обновляет метрики и список аномалий.

## Формат входных логов

Основной переключатель:

```dotenv
LOG_SOURCE_FORMAT=jsonl
```

Поддерживаются два формата:
- `jsonl` — структурированные строки JSON
- `plain` — обычный текстовый access-log Nginx

Для JSON можно переназначить поля:

```dotenv
LOG_FIELD_MAPPING={"timestamp":["ts"],"remote_addr":["clientIp"],"path":["requestPath"],"status":["statusCode"],"bytes_sent":["bytes"],"request_time":["latency"],"user_agent":["agent"]}
```

Для текстовых логов можно задать собственные шаблоны:

```dotenv
LOG_PLAIN_PATTERNS=["(?P<remote_addr>\\\\S+) (?P<ident>\\\\S+) (?P<remote_user>\\\\S+) \\\\[(?P<time_local>[^\\\\]]+)\\\\] \\\"(?P<request>[^\\\"]*)\\\" (?P<status>\\\\d{3}) (?P<bytes_sent>\\\\S+) \\\"(?P<referrer>[^\\\"]*)\\\" \\\"(?P<user_agent>[^\\\"]*)\\\"(?: (?P<request_time>[\\\\d.]+))?$"]
```

## Docker

Только API:

```bash
docker compose up --build
```

API, Prometheus и Grafana:

```bash
docker compose -f docker-compose.monitoring.yml up --build
```

Сервисы:

| Сервис | Порт | Адрес |
|--------|------|-------|
| API | 8000 | http://localhost:8000 |
| Prometheus | 9090 | http://localhost:9090 |
| Grafana | 3000 | http://localhost:3000 |

Grafana: логин `admin`, пароль `admin`.

## Конфигурация

Основные переменные `.env`:

| Переменная | По умолчанию | Назначение |
|------------|--------------|------------|
| `ARTIFACT_DIR` | `./artifacts` | каталог артефактов модели |
| `MODEL_TYPE` | `isolation_forest` | тип модели |
| `ANOMALY_THRESHOLD` | `0.5` | запасной порог для ML-детектора |
| `BASELINE_THRESHOLD` | `0.85` | порог для baseline |
| `LOG_SOURCE_FORMAT` | `jsonl` | формат входного журнала |
| `LOG_FIELD_MAPPING` | встроенный mapping | маппинг полей JSON |
| `LOG_PLAIN_PATTERNS` | встроенный regex | шаблоны для plain-логов |
| `AUTO_TRAIN_ON_STARTUP` | `false` | автообучение при старте |
| `BOOTSTRAP_LOG_PATH` | `./data/logs/bootstrap.jsonl` | файл для автообучения |
| `AUTO_INGEST_LOG_FILES_ON_STARTUP` | `false` | читать ли файлы логов при старте |
| `LOG_INPUT_PATHS` | `[]` | список файлов логов для чтения |
| `INGEST_BATCH_SIZE` | `500` | размер пакета при обработке |
| `MAX_STORED_ANOMALIES` | `1000` | сколько аномалий хранить в памяти |
| `LOG_LEVEL` | `INFO` | уровень логирования |

`LOG_INPUT_PATHS` можно задать как JSON-массив или как строку с путями через запятую.

## Публичная версия

- не содержит обучающих и валидационных логов;
- не содержит экспортированных артефактов модели;
- не содержит пояснительной записки и локальных служебных файлов;
- сохраняет код приложения, тесты, генераторы данных и конфигурацию мониторинга.

## Проверки

```bash
python3 -m compileall api core services detectors scripts tests
.venv/bin/python -m pytest -q
```

## Лицензия

MIT
