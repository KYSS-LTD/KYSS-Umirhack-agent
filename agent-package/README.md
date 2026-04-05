# Agent package (standalone)

Этот пакет можно **скопировать на сервер целиком** и запустить агент одной командой Docker Compose.

## 1) Подготовка
```bash
cp .env.example .env
# заполните BASE_URL и REGISTRATION_TOKEN
```

## 2) Запуск
```bash
docker compose up -d --build
```

> Данные агента (ключи + `config.json` с `agent_uid`) теперь хранятся в локальной папке `./agent-data` рядом с `docker-compose.yml`.
> Это значит, что два разных репозитория/папки запускают **два независимых агента** по умолчанию.

## 3) Проверка логов
```bash
docker compose logs -f kyss-agent
```

## Несколько агентов на одной машине
- Не используется фиксированный `container_name`, поэтому Compose не перетирает контейнеры между разными проектами.
- Для нового независимого агента достаточно запускать пакет из другой папки (будет другая `./agent-data`).
- Если нужно пересоздать идентичность в текущей папке:
  ```bash
  rm -rf agent-data
  docker compose up -d --build
  ```

## Что сделано для безопасности
- контейнер запущен от non-root пользователя;
- read-only root filesystem;
- отдельный volume `/agent-data` только для ключей и config;
- `no-new-privileges`, `cap_drop: [ALL]`, `pids_limit`, лимиты CPU/RAM;
- TLS verification включена по умолчанию (`VERIFY_TLS=true`).
- `run_command` выполняется только из allowlist и только через trusted binaries (`/bin`, `/usr/bin`, `/usr/sbin`, `/sbin`) без shell.

## Предустановленные инструменты в образе
В изолированный Docker-образ агента добавлены утилиты диагностики:
- `procps` (`uptime`, `free`),
- `iproute2`, `iputils-ping`, `net-tools`,
- `dnsutils`, `curl`, `ca-certificates`.

Это убирает ошибки вида «команда не найдена» при выполнении задач и ручной диагностике в контейнере.

## Отказоустойчивость
- если DNS/сеть недоступны при старте, агент **не падает**, а уходит в retry с backoff;
- при потере сети агент продолжает попытки и сам восстанавливается после возврата сети;
- при `401 Unauthorized` агент автоматически перерегистрируется с тем же `agent_uid` и обновляет токен.

## Troubleshooting
- `No address associated with hostname`: неверный `BASE_URL` или DNS недоступен для Docker.
- `[SSL] record layer failure`: чаще всего перепутан протокол. Для `http://...` не нужен TLS, для `https://...` нужен корректный сертификат.
- `exited with code 137`: обычно это `SIGKILL` (часто OOM или слишком жёсткие лимиты контейнера).
  - В `.env` увеличьте `AGENT_MEM_LIMIT` (например `768m`/`1g`) и при необходимости `AGENT_CPUS_LIMIT`.
  - После изменения лимитов перезапустите: `docker compose up -d --build`.
  - При `docker compose up --build` разовый `137` может появляться во время штатного recreate старого контейнера.

## Обновление
```bash
docker compose pull && docker compose up -d
```
(или `--build`, если пакет изменён локально).
