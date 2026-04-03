import sys
from overseer.config import Config
from overseer.database import create_pool
from overseer.watcher import Watcher


def main() -> None:
    config = Config()
    try:
        config.validate()
    except EnvironmentError as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)

    pool = create_pool(config)
    watcher = Watcher(config, pool)
    watcher.run()


if __name__ == "__main__":
    main()