import grp
import os
import pwd
import sys

import click

from opendkim_rotate_keys.key_table import *
from opendkim_rotate_keys.manager import *
from opendkim_rotate_keys.utils import *


@click.command()
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
    "--opendkim-genkey",
    default="/usr/sbin/opendkim-genkey",
    help="Path to the opendkim-genkey executable",
)
def cli(
    opendkim_conf,
    opendkim_keys_basedir,
    opendkim_genkey,
):
    print(opendkim_genkey)


def main(verbose):
    manager = Manager(verbose)
    manager.opendkim_conf = "/etc/opendkim.conf"
    manager.opendkim_keys_basedir = "/etc/dkimkeys"
    manager.opendkim_genkey = "/usr/bin/opendkim-genkey"
    manager.opendkim_testkey = "/usr/bin/opendkim-testkey"
    manager.key_owner = "opendkim"
    manager.key_owner_uid = pwd.getpwnam(manager.key_owner).pw_uid
    manager.key_group = "opendkim"
    manager.key_group_gid = grp.getgrnam(manager.key_group).gr_gid

    manager.dns_provider = create_dns_provider("linode")
    manager.keytable_path = get_keytable_path(manager.opendkim_conf)

    manager.keytable = KeyTable(manager.keytable_path)

    manager.rotate_keys()


if __name__ == "__main__":
    if os.getenv("USER") != "root":
        print("Error: script must be run as root")
        sys.exit(os.EX_USAGE)

    main(len(sys.argv) == 2 and sys.argv[1] == "-v")
