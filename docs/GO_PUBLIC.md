# PRAHARÍ — Go-Public & Submission Checklist

A short pre-flight before flipping the repo public for judges. Everything under
"Verified" was checked on 2026-07-05 and is green; the "You do" items are the
remaining human steps.

## Verified clean (safe to publish)

- [x] **No secrets in git history** — `git log --all -p | grep sk-ant` → none; `.env` never committed.
- [x] **No large/binary bloat** — no tracked file > 5 MB; `.venv`, `node_modules`, `__pycache__`, `data/*` gitignored.
- [x] **No ground-truth / data artifacts tracked** — `events.jsonl`, `ueba_scores.csv`, `ground_truth.json`, `attribution_report.json` all gitignored; only `data/README.md` + 11 threat-intel advisories are tracked (the RAG corpus).
- [x] **No `gt_*` leakage in the API** — 8/8 endpoints clean (`VERIFICATION_REPORT.md`).
- [x] **Docs consistent** — every internal link, `make` target, and screenshot referenced resolves; headline numbers consistent across all docs.
- [x] **LICENSE present** — MIT (`LICENSE`). *If you want a patent grant for the commercial roadmap, swap to Apache-2.0 before going public — say the word.*
- [x] **CI green** on `main` (badge in README will render once public).

## You do (human steps)

- [ ] **Add teammates** — README "Team & license" has a comment stub (`<!-- + teammates -->`); add names, or leave solo.
- [ ] **Record the demo video** — follow `docs/DEMO_SCRIPT.md` (pre-flight now uses `make attribute-agent-live`, no API key). Upload (YouTube unlisted / Drive) and paste the link into `SUBMISSION.md` and the README.
- [ ] **(Optional) Refresh the deck** — `docs/PRAHARI_Pitch_Deck.pptx`.
- [ ] **Flip public** when the above are done:

```bash
gh repo edit Kartik-99999/prahari --visibility public --accept-visibility-change-consequences
```

- [ ] **After going public**, open the repo in a logged-out browser and confirm: CI badge renders, README screenshots load, no private submodule/asset 404s.

## One-line submission-readiness summary (paste-ready)

> PRAHARÍ — behavioural cyber-resilience for CNI. One closed, auditable loop
> (ingest → UEBA → graph fusion → ATT&CK attribution → SOAR → hash-chained audit).
> Public benchmark CIC-IDS-2017 macro ROC **0.845**; held-out insider generalization
> ROC **0.9987** at 100% recall/1% FPR; OT/Modbus ROC 0.840→**0.895** (G7);
> ATT&CK attribution **92.3%** (deterministic) with a live Claude agent that beats
> it **20-vs-2** on the held-out insider case; **75%** SOAR automation with
> platform-enforced human gates; tamper-evident audit ledger. Repo + docs + deck +
> demo. CI green.
