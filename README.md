# surveystamp

Сервис attestation-штампов: принимает сырой payload, считает SHA-256, подписывает Ed25519 и отдаёт проверяемую квитанцию. Хранилище — in-memory; сторонних зависимостей нет, только stdlib.

**Внимание!** Проект учебный — на нём отрабатываются архитектура и TDD, а не готовится прод-сервис «из коробки».

## Запуск

```bash
go build -o surveystamp ./cmd/
./surveystamp

# просто запуск
go run ./cmd/

# HTTP через curl
curl -s -X POST localhost:9696/attestations -d '{"q":1}'
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST localhost:9696/attestations/<id>/verify

go test ./... -race -count=1
```

Слушает `:9696` (хардкод). Остановка — Ctrl+C (graceful shutdown).

`POST /attestations` → `201` и JSON (`id`, `hash`, `stamped`, `signature`).  
`POST /attestations/{id}/verify` → `204` или ошибка (`404` / `422`).

## Устройство

Код намеренно разбит на мелкие блоки (`domain`, `ports`, `app`, адаптеры `mem` / `crypt` / `api`, wiring в `cmd`), чтобы границы DDD и Clean Architecture были видны глазом. На таком объёме всё легко схлопнуть в пару файлов - здесь как раз наоборот: слои разделены ради наглядности, а не из-за размера продукта.
