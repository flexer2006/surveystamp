# surveystamp

An attestation stamping service: accepts a raw payload, computes its SHA-256 hash, signs it with Ed25519, and returns a verifiable receipt. Storage is in-memory; there are no third-party dependencies, only the standard library.

**Note!** This is an educational project intended to practice architecture and TDD, not to build a production-ready service out of the box.

## Running

```bash
go build -o surveystamp ./cmd/
./surveystamp

# just run
go run ./cmd/

# HTTP via curl
curl -s -X POST localhost:9696/attestations -d '{"q":1}'
curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST localhost:9696/attestations/<id>/verify

go test ./... -race -count=1
```

Listens on `:9696` (hardcoded). Stop with Ctrl+C (graceful shutdown).

`POST /attestations` → `201` and JSON (`id`, `hash`, `stamped`, `signature`).
`POST /attestations/{id}/verify` → `204` or an error (`404` / `422`).

## Architecture

The code is intentionally split into small components (`domain`, `ports`, `app`, `mem` / `crypt` / `api` adapters, wiring in `cmd`) so that the boundaries of DDD and Clean Architecture are clearly visible. At this scale, everything could easily be collapsed into a couple of files—in this project, the opposite approach is taken: the layers are separated for clarity rather than because of the product's size.
