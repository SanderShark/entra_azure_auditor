"""Enables ``python -m entra_auditor`` (same as the ``auditor`` console command)."""

if not __package__:
    # `python entra_auditor ...` runs this file as a loose script, where the relative import below can't work.
    raise SystemExit(
        "Run it as a module:\n"
        "    python -m entra_auditor --help\n"
        "or install it (pip install -e .) and use the `auditor` command."
    )

from .cli import main  # noqa: E402

if __name__ == "__main__":
    main()
