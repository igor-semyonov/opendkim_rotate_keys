import os
import shutil
import tempfile

from opendkim_rotate_keys.key_table import KeyTable


def test_how_it_works():
    import tempfile

    # Create a temporary file with contents
    with tempfile.NamedTemporaryFile(
        mode="w+t", delete=False
    ) as temp_file:
        temp_file.write(
                """\
dkim._domainkey.nalgor.net       nalgor.net:20250119595981:/var/lib/opendkim/nalgor.net.private

dkim._domainkey.semyonov.xyz     semyonov.xyz:20250119595981:/var/lib/opendkim/semyonov.xyz.private

                """
        )
        temp_file_name = temp_file.name

    key_table = KeyTable(temp_file_name)
    print(key_table.entries)



class TestKeyTable:
    def setup_class(self):
        self.key_table_file = tempfile.mkstemp()[1]

    def teardown_class(self):
        os.unlink(self.key_table_file)

    def write_key_file_contents(self, keyfile):
        with open(self.key_table_file, "w") as f:
            for short_name in keyfile:
                line = "{}  {}:{}:{}\n".format(
                    short_name,
                    keyfile[short_name][KeyTable.DOMAIN],
                    keyfile[short_name][KeyTable.SELECTOR],
                    keyfile[short_name][
                        KeyTable.PRIVATE_KEY
                    ],
                )
                f.write(line)

    def test_simple_load(self):
        key_dir = tempfile.mkdtemp()

        try:
            keyfile = {
                "example": {
                    KeyTable.DOMAIN: "example.com",
                    KeyTable.SELECTOR: "20170101",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/example.private",
                },
                "replacehandsaw": {
                    KeyTable.DOMAIN: "replacehandsaw.test",
                    KeyTable.SELECTOR: "20170201",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/replacehandsaw.private",
                },
            }

            self.write_key_file_contents(keyfile)
            keytable = KeyTable(self.key_table_file)

            assert 2 == len(keytable)

            for short_name, values in keytable:
                assert short_name in keyfile
                assert (
                    keyfile[short_name][KeyTable.DOMAIN]
                    == values[KeyTable.DOMAIN]
                )
                assert (
                    keyfile[short_name][KeyTable.SELECTOR]
                    == values[KeyTable.SELECTOR]
                )
                assert (
                    keyfile[short_name][
                        KeyTable.PRIVATE_KEY
                    ]
                    == values[KeyTable.PRIVATE_KEY]
                )
        finally:
            shutil.rmtree(key_dir)

    def test_sorted_by_short_name(self):
        key_dir = tempfile.mkdtemp()

        try:
            keyfile = {
                "foo": {
                    KeyTable.DOMAIN: "foo.test",
                    KeyTable.SELECTOR: "20170101",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/foo.test",
                },
                "bar": {
                    KeyTable.DOMAIN: "bar.test",
                    KeyTable.SELECTOR: "20170201",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/bar.test",
                },
                "apple": {
                    KeyTable.DOMAIN: "apple.test",
                    KeyTable.SELECTOR: "20170201",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/apple.test",
                },
            }

            self.write_key_file_contents(keyfile)
            keytable = KeyTable(self.key_table_file)

            assert 3 == len(keytable)

            assert (
                keyfile["apple"][KeyTable.DOMAIN]
                == keytable[0][KeyTable.DOMAIN]
            )
            assert (
                keyfile["bar"][KeyTable.DOMAIN]
                == keytable[1][KeyTable.DOMAIN]
            )
            assert (
                keyfile["foo"][KeyTable.DOMAIN]
                == keytable[2][KeyTable.DOMAIN]
            )
        finally:
            shutil.rmtree(key_dir)

    def test_short_name_padding(self):
        key_dir = tempfile.mkdtemp()

        try:
            keyfile = {
                "unitedmonkey": {
                    KeyTable.DOMAIN: "foo.test",
                    KeyTable.SELECTOR: "20170101",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/foo.test",
                },
                "bar": {
                    KeyTable.DOMAIN: "bar.test",
                    KeyTable.SELECTOR: "20170201",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/bar.test",
                },
                "apple": {
                    KeyTable.DOMAIN: "apple.test",
                    KeyTable.SELECTOR: "20170201",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/apple.test",
                },
            }

            self.write_key_file_contents(keyfile)
            keytable = KeyTable(self.key_table_file)

            assert 3 == len(keytable)

            keytable.save_changes()

            selector_format = (
                "{:"
                + str(
                    len("unitedmonkey")
                    + KeyTable.SELECTOR_PADDING
                )
                + "}{}"
            )

            with open(self.key_table_file) as f:
                lines = f.read().splitlines()

            for selector, i in [
                ("apple", 0),
                ("bar", 1),
                ("unitedmonkey", 2),
            ]:
                beginningtext = selector_format.format(
                    selector,
                    keyfile[selector][KeyTable.DOMAIN],
                )
                assert lines[i].startswith(beginningtext)
        finally:
            shutil.rmtree(key_dir)

    def test_update_selector(self):
        key_dir = tempfile.mkdtemp()

        try:
            keyfile = {
                "orangeauto": {
                    KeyTable.DOMAIN: "orangeauto.test",
                    KeyTable.SELECTOR: "20170101",
                    KeyTable.PRIVATE_KEY: key_dir
                    + "/orangeauto.test",
                }
            }

            self.write_key_file_contents(keyfile)
            keytable = KeyTable(self.key_table_file)

            assert 1 == len(keytable)
            assert (
                "20170101"
                == keytable.entries["orangeauto"][
                    KeyTable.SELECTOR
                ]
            )

            keytable.update_selector(
                "orangeauto", "20170201"
            )
            assert (
                "20170201"
                == keytable.entries["orangeauto"][
                    KeyTable.SELECTOR
                ]
            )
        finally:
            shutil.rmtree(key_dir)
