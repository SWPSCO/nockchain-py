"""Local, interactive transaction inspection and signing."""

import argparse
import getpass
import hashlib
import json
import os
import stat
import sys

from .keys import parse_extended_key
from .seed import restore_wallet
from .signing import inspect_signing_bundle, sign_signing_bundle


def _read_bounded(path, maximum):
    with open(path, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("expected a bounded regular file")
        result = handle.read(maximum + 1)
        if len(result) > maximum:
            raise ValueError("file is too large")
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect and sign Nockblocks bundles locally.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect", help="validate a bundle and print its review")
    inspect.add_argument("bundle")
    sign = subparsers.add_parser("sign", help="review and sign in an interactive terminal")
    sign.add_argument("bundle")
    sign.add_argument("--out", required=True, help="create a new signed bundle file")
    sign.add_argument("--key-file", help="local plain-text zprv or recovery phrase")
    sign.add_argument("--mnemonic", action="store_true", help="use a recovery phrase")
    sign.add_argument(
        "--path", help="explicit child derivation path; required for recovery phrases"
    )
    sign.add_argument("--passphrase", action="store_true", help="prompt for a recovery passphrase")
    args = parser.parse_args(argv)
    try:
        if args.command == "sign":
            if args.mnemonic and not args.path:
                raise ValueError("--mnemonic requires an explicit --path")
            if args.passphrase and not args.mnemonic:
                raise ValueError("--passphrase requires --mnemonic")
        raw = _read_bounded(args.bundle, 8 * 1024 * 1024)
        inspected = inspect_signing_bundle(json.loads(raw))
        if args.command == "inspect":
            print(json.dumps(inspected.review, indent=2))
            return 0
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValueError("signing requires an interactive terminal for review and approval")
        print(json.dumps(inspected.review, indent=2), file=sys.stderr)
        print(
            "Network and tip are indexed context, not proof that inputs are unspent.",
            file=sys.stderr,
        )
        print(f"Bundle SHA-256: {hashlib.sha256(raw).hexdigest()}", file=sys.stderr)
        print(
            "Check recipients, amounts and fee. Type SIGN to approve: ",
            end="",
            file=sys.stderr,
            flush=True,
        )
        if input() != "SIGN":
            raise ValueError("signing declined; no output written")
        secret = (
            _read_bounded(args.key_file, 16384).decode().strip()
            if args.key_file
            else getpass.getpass(
                "Recovery phrase (hidden): " if args.mnemonic else "zprv (hidden): ",
                stream=sys.stderr,
            )
        )
        passphrase = (
            getpass.getpass("Passphrase (hidden): ", stream=sys.stderr) if args.passphrase else ""
        )
        key = restore_wallet(secret, passphrase) if args.mnemonic else parse_extended_key(secret)
        if args.path:
            key = key.derive(args.path)
        signed = sign_signing_bundle(inspected.bundle, key)
        descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(signed, output, indent=2)
            output.write("\n")
        print(
            json.dumps(
                {
                    "output": args.out,
                    "transactionId": inspect_signing_bundle(signed).review["transactionId"],
                    "fullySigned": True,
                },
                indent=2,
            )
        )
        return 0
    except (ValueError, TypeError, KeyError, OSError, EOFError, KeyboardInterrupt) as error:
        print(f"nockchain: {error or 'signing cancelled'}", file=sys.stderr)
        return 1
