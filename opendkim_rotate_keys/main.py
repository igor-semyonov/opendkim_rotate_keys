import logging
import os
import sys

import click

#  from opendkim_rotate_keys.key_table import *
from opendkim_rotate_keys.manager import Manager

#  from opendkim_rotate_keys.utils import *

logger = logging.getLogger(__name__)


def start_logging():
    logging.basicConfig(
        #  filename="opendkim_rotate_keys.log",
        level=logging.INFO,
    )


@click.command()
@click.option(
    "-v",
    "--verbose",
    default=False,
    is_flag=True,
    help="Be verbose",
)
@click.option(
    "--opendkim-conf",
    default="/etc/opendkim/opendkim.conf",
    help="Path to the OpenDKIM config file",
)
@click.option(
    "--opendkim-keys-basedir",
    default="/var/lib/opendkim",
    help="OpenDKIM key store directory",
)
@click.option(
    "--dns-provider",
    default="linode",
    help="DNS provider",
)
@click.option(
    "-D",
    "--delete-older-than",
    default=30_000,
    help="Delete TXT DKIM domainkey records older than this many days old. Defaults to 30,000",
)
def cli(
    verbose: bool,
    opendkim_conf: str,
    opendkim_keys_basedir: str,
    dns_provider: str,
    delete_older_than: int,
):
    start_logging()
    manager = Manager(
        verbose=verbose,
        opendkim_conf=opendkim_conf,
        opendkim_keys_basedir=opendkim_keys_basedir,
        dns_provider=dns_provider,
        delete_older_than=delete_older_than,
    )

    manager.rotate_keys()


if __name__ == "__main__":
    if os.getenv("USER") != "root":
        print("Error: script must be run as root")
        sys.exit(os.EX_USAGE)

    main(len(sys.argv) == 2 and sys.argv[1] == "-v")
