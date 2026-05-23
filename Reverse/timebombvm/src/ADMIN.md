# TimeBomb VM — Admin Notes

## Build dist binary

The distributed artifact `dist/timebombvm` is built from `src/vm/`.

Recommended (uses Docker + Alpine musl):

```bash
cd dist
chmod +x build_dist.sh
./build_dist.sh
```

This will place the ELF at `dist/timebombvm`.

## Run locally (docker-compose)

From the challenge root:

```bash
cd src
docker compose up --build
```

Then in another terminal:

```bash
nc 127.0.0.1 8011
```

## End-to-end test (official solver)

```bash
# in one terminal
cd src && docker compose up --build

# in another terminal
python3 ../solver/solve.py 127.0.0.1 8011
```

## Notes

- Ensure executable bits are set:
  - `src/run.sh`
  - `dist/build_dist.sh`
- The service runs as user `ctf` (uid 1001), not root.
- The flag is stored in `src/flag.txt` inside the container.
