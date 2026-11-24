import argparse
from importlib.metadata import version


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cybertriage",
        description="Investigate Wazuh alerts using evidence and reference knowledge.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberTriage {version('cybertriage')}",
    )

    parser.parse_args()
    parser.print_help()


if __name__ == "__main__":
    main()