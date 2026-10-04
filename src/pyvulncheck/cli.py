"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pyvulncheck.report import (
    exit_code, render_json, render_sarif, render_text, use_colour,
)
from pyvulncheck.scanner import scan

DESCRIPTION = """\
Reachability-based vulnerability triage for Python.

pip-audit tells you a vulnerable version is installed. pyvulncheck tells you
whether your code can actually call the vulnerable function.
"""

EPILOG = """\
examples:
  pyvulncheck .                        scan the current project
  pyvulncheck src/ --all               include advisories with no call path
  pyvulncheck . --format sarif         emit SARIF for GitHub code scanning
  pyvulncheck . --offline              use only the local cache, no network
  pyvulncheck . --fail-on possible     stricter CI gate

exit codes:
  0  nothing at or above the --fail-on threshold
  1  threshold met (default: a REACHABLE finding)
  2  the scan itself failed
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyvulncheck",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=".", help="project directory to scan (default: .)")
    parser.add_argument("-r", "--requirements", type=Path,
                        help="also take pinned versions from a requirements file")
    parser.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text",
                        help="output format (default: text)")
    parser.add_argument("-o", "--output", type=Path, help="write the report to a file")
    parser.add_argument("-a", "--all", action="store_true", dest="show_all",
                        help="also list advisories with no reachable call path")
    parser.add_argument("--fail-on", choices=("reachable", "possible", "unknown", "any", "never"),
                        default="reachable", help="exit 1 when a finding at this level exists")
    parser.add_argument("--offline", action="store_true",
                        help="never hit the network; use the cache only")
    parser.add_argument("--no-derive", action="store_true",
                        help="skip deriving symbols from fix commits (curated data only)")
    parser.add_argument("--no-deps", action="store_true",
                        help="do not parse dependency source (first-party code only)")
    parser.add_argument("--max-depth", type=int, default=12,
                        help="maximum call-path length to search (default: 12)")
    parser.add_argument("--curated-dir", type=Path,
                        help="override the curated advisory dataset directory")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--version", action="store_true", help="print the version and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from pyvulncheck import __version__

        print(f"pyvulncheck {__version__}")
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    def progress(message: str) -> None:
        if not args.quiet and args.format == "text":
            print(f"  ... {message}", file=sys.stderr)

    try:
        result = scan(
            target,
            requirements=args.requirements,
            offline=args.offline,
            derive_symbols=not args.no_derive,
            follow_dependencies=not args.no_deps,
            max_depth=args.max_depth,
            curated_dir=args.curated_dir,
            progress=progress,
        )
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 2

    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    if result.errors and not result.findings:
        return 2

    if args.format == "json":
        output = render_json(result.findings, stats=result.stats)
    elif args.format == "sarif":
        output = render_sarif(result.findings)
    else:
        colour = {"always": True, "never": False}.get(args.color)
        stream = sys.stdout if not args.output else None
        output = render_text(
            result.findings,
            colour=use_colour(stream or sys.stdout, colour) if not args.output else False,
            show_all=args.show_all,
            stats=result.stats,
            scanned=result.stats,
        )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(output)

    return exit_code(result.findings, fail_on=args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
