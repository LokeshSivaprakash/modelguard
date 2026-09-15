# ModelGuard demo walkthrough

A self-contained demo you can run in about 5 minutes, no Hugging Face
account or real model download required. It builds two synthetic pickle
fixtures in-process (never executed — see the safety note below), scans
them, correlates, and shows the CI gate blocking a deploy.

## 1. Start Postgres and apply the schema

```bash
docker compose up -d
cp .env.example .env   # defaults match docker-compose.yml, no edits needed
pip install -r requirements.txt
python cli.py init-db
```

## 2. Build the demo model directory

`demo/fixtures/toy-classifier/` is *not* checked into the repo (see
`.gitignore` — binary pickle fixtures don't belong in git history, and
shipping a "malicious" file by default is a bad look for a security repo
regardless of how inert it actually is). Generate it locally instead:

```bash
python demo/make_demo_fixtures.py
```

This writes three files that mirror what a real model repo looks like:

- `model.safetensors` — safe by construction, not scanned
- `preprocessor_state.pkl` — an ordinary pickled object, no findings
- `pytorch_model.bin` — a pickle whose `__reduce__` references `os.system`,
  the same primitive real malicious model files on public hubs have used

**Safety note:** `make_demo_fixtures.py` builds the malicious fixture with
`pickle.dumps()`, which calls `__reduce__` *at dump time* to decide what to
serialize — it does not execute the callable it references. `os.system` is
never actually invoked while generating or scanning this fixture. That
distinction is the entire safety property this project depends on, and the
demo is built specifically to exercise it, not just claim it.

## 3. Run the pipeline

```bash
python cli.py scan-model --model-ref demo/toy-classifier --path ./demo/fixtures/toy-classifier --source local
python cli.py check-provenance --model-ref demo/toy-classifier --source local
python cli.py correlate
python cli.py report
```

Expect a risk score of 10.0 — `os.system` is a critical code-execution
finding, and the demo model's provenance is deliberately unverified, so both
of ModelGuard's correlation signals fire at once.

## 4. See the CI gate block it

```bash
python ci/gate.py --model-ref demo/toy-classifier --threshold 7.0
echo "exit code: $?"   # 1 — this is what fails a pull request
```

## 5. Export the AIBOM

```bash
python cli.py aibom --model-ref demo/toy-classifier --out toy-classifier.aibom.json
cat toy-classifier.aibom.json
```

## 6. Look at the dashboard

```bash
python cli.py dashboard
# open http://127.0.0.1:5060
```

## What this demo does *not* cover

Provenance checking against the live Hugging Face API (`check-provenance`
with `--source huggingface`) and pipeline CVE correlation (`scan-pipeline`,
which needs `syft`/`grype` installed) both work the same way against a real
model repo and a real inference environment — they're just not exercised
here to keep the demo dependency-free. See the main README's Quick Start for
running those against something real.
