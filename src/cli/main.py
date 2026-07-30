"""
main.py
-------
Command Line Interface (CLI) for the Docker Container Security Scanner.

Author: Richaa
"""

import argparse

from src.core.scanner import SecurityScanner
from src.core.dockerfile_analyzer import DockerfileAnalyzer


def build_parser():

    parser = argparse.ArgumentParser(
        prog="Docker Container Security Scanner",
        description="Docker Security Scanner CLI"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    # --------------------------------------------------
    # IMAGE SCAN COMMAND
    # --------------------------------------------------

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Docker image"
    )

    scan_parser.add_argument(
        "--image",
        required=True,
        help="Docker image name"
    )

    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    # --------------------------------------------------
    # DOCKERFILE ANALYSIS COMMAND
    # --------------------------------------------------

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a Dockerfile"
    )

    analyze_parser.add_argument(
        "--dockerfile",
        required=True,
        help="Path to Dockerfile"
    )

    return parser


def main():

    parser = build_parser()

    args = parser.parse_args()

    # ==============================================
    # IMAGE SCAN
    # ==============================================

    if args.command == "scan":

        print("\n========================================")
        print(" Docker Container Security Scanner")
        print("========================================")

        print(f"\n[*] Image  : {args.image}")
        print(f"[*] Format : {args.format}\n")

        scanner = SecurityScanner()

        scanner.scan_image(args.image)

    # ==============================================
    # DOCKERFILE ANALYSIS
    # ==============================================

    elif args.command == "analyze":

        print("\n========================================")
        print(" Dockerfile Security Analyzer")
        print("========================================")

        print(f"\n[*] Dockerfile : {args.dockerfile}")

        analyzer = DockerfileAnalyzer()

        try:

            analyzer.analyze(args.dockerfile)

            analyzer.print_report()

        except FileNotFoundError as e:

            print(f"\n[-] {e}")

        except Exception as e:

            print(f"\n[-] Unexpected Error: {e}")


if __name__ == "__main__":
    main()