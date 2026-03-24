# log-anomaly-detector

Ищет аномалии в nginx access-логах и объясняет их через MITRE ATT&CK.

Парсит JSONL и plain-text, вытаскивает 26 признаков из каждого запроса, прогоняет через Isolation Forest, а найденные аномалии размечает техниками MITRE. Отдаёт всё через REST API + Prometheus.

## Структура

```
api/          FastAPI
core/         модели данных, нормализация, настройки
services/     парсинг, признаки, MITRE, обучение, хранилище
detectors/    baseline, Isolation Forest, реестр моделей
scripts/      обучение, валидация, генерация логов
tests/        тесты
grafana/      дашборд
prometheus/   конфиг
```

`data/` и `artifacts/` локальные, в репу не входят.

## Установка

```bash
uv sync --extra dev
```

## Обучение

```bash
# обычное
PYTHONPATH=. uv run python3 scripts/train.py --input data/logs/train.jsonl --model isolation_forest

# потоковое (не грузит весь файл в память)
PYTHONPATH=. uv run python3 scripts/train_large.py --input data/logs/train.jsonl

# валидация
PYTHONPATH=. uv run python3 scripts/validate_model.py --input data/logs/validation.jsonl
```

Можно сгенерить синтетику:

```bash
PYTHONPATH=. uv run python3 scripts/generate_logs.py --total 5000 --anomaly-ratio 0.05
```

## Запуск

```bash
PYTHONPATH=. uv run uvicorn api.main:app --reload --port 8000
```

### API

```
GET  /health        статус
POST /ingest        кинуть логи (поле lines)
GET  /anomalies     последние аномалии
GET  /metrics       prometheus
GET  /metrics/json  метрики json
```

### Файлы при старте

Можно не слать логи через API, а указать файлы в `.env`:

```
AUTO_INGEST_LOG_FILES_ON_STARTUP=true
LOG_INPUT_PATHS=["./data/logs/input.jsonl"]
```

## Формат логов

`LOG_SOURCE_FORMAT=jsonl` (default) или `plain`. Маппинг полей настраивается через `LOG_FIELD_MAPPING`, regex для plain — через `LOG_PLAIN_PATTERNS`. Примеры в `.env.example`.

## Docker

```bash
docker compose up --build                                    # только API
docker compose -f docker-compose.monitoring.yml up --build   # + prometheus + grafana
```

Grafana на :3000 (admin/admin), Prometheus на :9090.

## Конфигурация

Через `.env`, см. `.env.example`. Основное:

- `MODEL_TYPE` — `isolation_forest` или `baseline`
- `ANOMALY_THRESHOLD` / `BASELINE_THRESHOLD` — пороги
- `LOG_SOURCE_FORMAT` — `jsonl` / `plain`
- `AUTO_TRAIN_ON_STARTUP` — обучить модель при старте
- `INGEST_BATCH_SIZE` — размер батча

## Тесты

```bash
PYTHONPATH=. uv run python3 -m pytest
```
