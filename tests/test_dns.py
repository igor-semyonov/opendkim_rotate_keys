from opendkim_rotate_keys.dns.providers import (
    LinodeDnsProvider,
)


def test_get_domains():
    ldp = LinodeDnsProvider()
    ldp.get_domains()
    print(ldp.domains)
    #  ldp.create_txt_record("nalgor.net", "meow", "mix")
    #  records = ldp.get_records()
    #  print(records)
