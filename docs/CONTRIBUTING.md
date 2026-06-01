# Contributing

Thanks for your interest in contributing to the Cloud Threat Detection System. This document outlines how to set up the repository, development workflow, and standards.

## Repository Setup

1. Fork the repository and clone your fork.
2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

3. Copy `.env.example` to `.env` and populate secrets (database URL, JWT secret keys).

## Development Workflow

- Create a feature branch from `main` with a descriptive name: `feat/<short-description>` or `fix/<short-description>`.
- Keep commits focused and atomic.

## Branch Naming

- `feat/<name>` — new features
- `fix/<name>` — bug fixes
- `chore/<name>` — maintenance
- `docs/<name>` — documentation changes

## Commit Message Standards

Use conventional commits style (short summary, optional body):

```
feat(auth): add refresh token endpoint

Add support for refresh tokens to allow long-lived sessions.
```

## Pull Request Process

1. Open a PR against `main` with a clear description and related issue if available.
2. Ensure tests pass and include unit tests for new behavior.
3. Include changelog entry in PR when applicable.

## Code Style Expectations

- Follow Python best practices (PEP8). Use black or the project's formatter if present.
- Keep functions small and focused; add docstrings for public functions and classes.

## Tests

- Add tests under `backend/tests` and run them with `pytest`.
