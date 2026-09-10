from __future__ import annotations

import json
import logging
import sys

from sentinova_threatlens.config import AppConfig
from sentinova_threatlens.pipeline import IngestionPipeline


def _run_cli() -> None:
    config = AppConfig()
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)-7s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    logger = logging.getLogger("sentinova_threatlens")

    logger.info("Sentinova Threatlens CTI Ingestion Engine starting")

    try:
        pipeline = IngestionPipeline(config)
        stats = pipeline.run()
    except Exception:
        logger.exception("Pipeline execution failed")
        sys.exit(1)

    print("\n=== Ingestion Summary ===")
    print(json.dumps(stats, indent=2, default=str))
    print("=========================\n")


def main() -> None:
    """Launch the desktop GUI by default; --headless for CLI ingestion only."""
    if "--headless" in sys.argv[1:]:
        _run_cli()
        return

    from sentinova_threatlens.gui.__main__ import main as gui_main

    gui_main()


if __name__ == "__main__":
    main()