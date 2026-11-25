# Contributing

1. Fork, create a branch (`feat/<tool-name>`), keep commits small and descriptive.
2. `pip install -r requirements-dev.txt && pytest -q` must pass.
3. **Adding a tool** = one decorated function in `app/tools/*.py` (see `docs/ARCHITECTURE.md`).
   The form, API route, audit log and report export appear automatically. Add tests.
4. Rules for new tools:
   - Read-only recon only: no exploitation, brute-forcing, credential guessing or cracking.
   - Any user-supplied host/URL **must** go through `app/core/security_guards.py`.
   - Never put secrets in logs: mark such fields `sensitive=True`, results `store_result=False`.
   - Render results with `textContent`, never `innerHTML`.
