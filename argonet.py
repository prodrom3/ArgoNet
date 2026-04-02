# Copyright (c) 2024 prodrom3 / radamic
# Licensed under the MIT License.
# Last updated: 2026-04-02

"""ArgoNet - Network reconnaissance toolkit."""

import asyncio
import logging
import signal
import sys
import threading

from core.cli import parse_args
from core.diff import diff_results, load_previous
from core.export import export_csv, export_html, export_map
from core.geo import GeoIPReader, ResultCache
from core.logging_config import setup_logging
from core.models import AnalysisResult
from core.output import Renderer
from core.pipeline import PipelineConfig, analyze_target

logger = logging.getLogger("argonet")

_shutdown = threading.Event()


def _handle_sigint(signum: int, frame: object) -> None:
    _shutdown.set()


def _install_signal_handler() -> object:
    try:
        return signal.signal(signal.SIGINT, _handle_sigint)
    except ValueError:
        return None


def _restore_signal_handler(prev: object) -> None:
    if prev is not None:
        try:
            signal.signal(signal.SIGINT, prev)  # type: ignore[arg-type]
        except (ValueError, OSError):
            pass


def _deduplicate(targets: list[str]) -> list[str]:
    return list(dict.fromkeys(targets))


async def _run(
    targets: list[str],
    geo_reader: GeoIPReader,
    cache: ResultCache,
    config: PipelineConfig,
    renderer: Renderer,
    workers: int,
) -> list[AnalysisResult]:
    if len(targets) == 1:
        return [await analyze_target(targets[0], geo_reader, config, cache)]

    sem = asyncio.Semaphore(workers)
    results_map: dict[str, AnalysisResult] = {}
    completed = 0
    total = len(targets)

    async def bounded_analyze(target: str) -> None:
        nonlocal completed
        if _shutdown.is_set():
            return
        async with sem:
            if _shutdown.is_set():
                return
            try:
                results_map[target] = await analyze_target(
                    target, geo_reader, config, cache,
                )
            except Exception as exc:
                logger.error("Analysis failed for %s: %s", target, exc)
                results_map[target] = AnalysisResult(
                    target=target, is_ip=False, error=str(exc),
                )
            completed += 1
            renderer.progress(completed, total, target)

    tasks = [asyncio.create_task(bounded_analyze(t)) for t in targets]
    await asyncio.gather(*tasks, return_exceptions=True)

    return [
        results_map.get(t, AnalysisResult(target=t, is_ip=False, error="Cancelled"))
        for t in targets
    ]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cache = ResultCache()
    unique_targets = _deduplicate(args.targets)

    renderer = Renderer(quiet=args.quiet or args.json_output)

    setup_logging(enable_file=not args.quiet)
    logger.info("ArgoNet started with %d target(s)", len(unique_targets))

    config = PipelineConfig.from_args(args)
    prev_handler = _install_signal_handler()

    try:
        with GeoIPReader(args.db, asn_db=args.asn_db) as geo_reader:
            show_db_warning = not geo_reader.available and not geo_reader.asn_available
            results = asyncio.run(
                _run(unique_targets, geo_reader, cache, config, renderer, args.workers)
            )
    finally:
        _restore_signal_handler(prev_handler)
        _shutdown.clear()

    # Output
    if args.json_output:
        renderer.json_output(results)
    else:
        for result in results:
            renderer.analysis(result, show_db_warning=show_db_warning)
            show_db_warning = False

    # Diff
    if args.diff:
        try:
            previous = load_previous(args.diff)
            current_dicts = [r.to_dict() for r in results]
            changes = diff_results(current_dicts, previous)
            renderer.diff_changes(changes)
        except (FileNotFoundError, ValueError) as e:
            renderer.error(f"Could not load diff file: {e}")

    # Exports
    if args.csv:
        export_csv(results, args.csv)
        logger.info("CSV exported to %s", args.csv)

    if args.html:
        export_html(results, args.html)
        logger.info("HTML report exported to %s", args.html)

    if args.map:
        export_map(results, args.map)
        logger.info("Geo map exported to %s", args.map)

    exit_code = 1 if any(r.has_errors for r in results) else 0
    logger.info("ArgoNet finished with exit code %d", exit_code)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
