from __future__ import print_function

import logging
import subprocess

from opendkim_rotate_keys.dns.providers import (
    DnsProvider,
    LinodeDnsProvider,
)

logger = logging.getLogger(__name__)

__all__ = [
    "toggle_services",
    "print_verbose",
    "print_header",
    "print_error",
    "get_keytable_path",
    "scrub_txt_record",
    "create_dns_provider",
]


def toggle_services(
    stop: bool,
    init_system: str = "openrc",
):
    action = "stop" if stop else "start"
    if init_system == "openrc":
        postfix_options = ["rc-service", "postfix", action]
        opendkim_options = ["rc-service", "opendkim", action]
    elif init_system == "systemd":
        postfix_options = ["systemctl", action, "postfix"]
        opendkim_options = ["systemctl", action, "opendkim"]
    else:
        raise f"Init system {init_system} is not supported."

    if stop:
        print_header("Stopping services...")
        print("Stopping Postfix...")
        subprocess.check_call(postfix_options)
        print("Stopping OpenDKIM...")
        subprocess.check_call(opendkim_options)
    else:
        print_header("Starting services...")
        print("Starting OpenDKIM...")
        subprocess.check_call(opendkim_options)
        print("Starting Postfix...")
        subprocess.check_call(postfix_options)


def print_verbose(message):
    print("\x1b[1;30;40m{}\x1b[0m".format(message))


def print_header(message):
    print("\x1b[1;33;40m{}\x1b[0m".format(message))


def print_error(message):
    print("\x1b[1;31;40m{}\x1b[0m".format(message))


def get_keytable_path(opendkim_conf):
    """Returns the path to the KeyTable file from the OpenDKIM config."""
    param = "KeyTable"

    with open(opendkim_conf, "r") as f:
        for line in f:
            if line.startswith(param):
                return line.replace(param, "").strip()

    msg = "Could not find '{}' parameter in OpenDKIM config at {}".format(
        param, opendkim_conf
    )
    raise RuntimeError(msg)


def scrub_txt_record(txt_value):
    txt = ""

    for line in txt_value.strip().split("\n"):
        first = line.index('"') + 1
        last = line.rindex('"')
        txt += line[first:last]

    return txt


def create_dns_provider(
    dns_provider,
) -> DnsProvider | LinodeDnsProvider:
    """Factory method to generate a DNS provider to create entries at."""

    if dns_provider == "linode":
        return LinodeDnsProvider()

    msg = "Unknown DNS provider '{}' specified".format(
        dns_provider
    )
    raise NameError(msg)
