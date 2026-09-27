# Releasing

Repository: https://github.com/realahsanshah/jev-action-firewall. Package: https://pypi.org/project/jev-firewall/.

A PyPI version can never be re-uploaded, even after you delete it. That's why every release
is checked three times: from the local wheel, from TestPyPI, and from PyPI.

## One-time setup (maintainer)

1. Create accounts on https://pypi.org and https://test.pypi.org (they are separate) and turn
   on 2FA. PyPI requires it for uploads.
2. Create an API token on each (Account settings → API tokens). For the first upload the
   scope has to be "Entire account", because the project doesn't exist yet. After 0.1.0 is
   up, replace it with a token scoped to `jev-firewall`.
3. Keep the tokens out of the repo. Put them in `.env` (gitignored; see `.env.example`), which
   `uv run --env-file .env` and a sourced shell both pick up. `uv publish` reads `UV_PUBLISH_TOKEN`.

## Release steps

```bash
# 1. green checks
uv run ruff check . && uv run mypy && uv run pytest

# 2. build and validate metadata / README rendering
rm -rf dist && uv build
uvx twine check --strict dist/*

# 3. pre-publish: install the wheel into fresh venvs, one per framework, and run the consumer examples
python scripts/verify_consumer_examples.py --source local                 # installs with pip
python scripts/verify_consumer_examples.py --source local --installer uv  # and with uv

# 4. TestPyPI dry run
UV_PUBLISH_TOKEN=<testpypi token> uv publish --publish-url https://test.pypi.org/legacy/ dist/*
python scripts/verify_consumer_examples.py --source testpypi

# 5. the real release (irreversible)
UV_PUBLISH_TOKEN=<pypi token> uv publish dist/*
python scripts/verify_consumer_examples.py --source pypi

# 6. tag
git tag -a v0.1.0 -m "jev-firewall 0.1.0" && git push origin master --tags
gh release create v0.1.0 --title "jev-firewall 0.1.0" --notes-file CHANGELOG.md dist/*
```

On PowerShell, set the token with `$env:UV_PUBLISH_TOKEN = "<token>"` before `uv publish`.

## Consumer examples

`examples/consumer/<extra>/` are standalone projects: `requirements.txt` pins
`jev-firewall[<extra>]==<version>`, plus a `policy.yaml` and an `app.py` that import nothing from
this repo. Bump the pins together with `version` in `pyproject.toml` and
`jev_firewall.__version__`.
