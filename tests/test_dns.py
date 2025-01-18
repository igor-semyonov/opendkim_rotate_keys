import os
import time

import pytest

from opendkim_rotate_keys.dns.providers import (
    LinodeDnsProvider,
)


@pytest.mark.skipif(
    "LINODE_API_KEY" not in os.environ,
    reason="API key not in environment variables",
)
def test_get_domains():
    ldp = LinodeDnsProvider()
    ldp.get_domains()
    print(ldp.domains)
    #  ldp.create_txt_record("nalgor.net", "meow", "mix")
    domain = "nalgor.net"

    ldp.create_txt_record(
        domain,
        "test",
        "test domain key contents",
    )
    time.sleep(10)

    records = ldp.get_records(domain)
    for record in records["data"]:
        if record["type"] == "TXT":
            if record["name"] == "test_domainkey":
                record_id = record["id"]
                _response = ldp.delete_txt_record(
                    domain, record_id
                )
