import logging

logger = logging.getLogger(__name__)


class KeyTable:
    """Allows parsing, editing, and saving OpenDKIM KeyTable files.

    See "KeyTable (dataset)" entry at
    http://www.opendkim.org/opendkim.conf.5.html
    """

    # Entries from the KeyTable file. Dictionary keyed by domain short name.
    # Values are an array containing: name of the domain ("d=" value),
    # selector ("s=" value), and path to private key.
    entries = {}

    # Copy of OpenDKIM KeyTable file before any modifications were made.
    original_conf_file = {}

    file_path = ""

    DOMAIN = "domain"
    SELECTOR = "selector"
    PRIVATE_KEY = "private_key"

    # Number of spaces to add to the longest short name when writing the
    # KeyTable file. All subsequent entries will be padded to match.
    SELECTOR_PADDING = 5

    def __init__(self, file_path: str):
        self.entries = {}
        self.original_conf_file = {}

        with open(file_path, "r") as f:
            for line in f:
                parts = line.split()
                try:
                    v = parts[1].split(":")
                except IndexError:
                    continue
                values = {
                    self.DOMAIN: v[0],
                    self.SELECTOR: v[1],
                    self.PRIVATE_KEY: v[2],
                }

                self.entries[parts[0]] = values
                self.original_conf_file[parts[0]] = values

        self.entries = dict(sorted(self.entries.items()))
        self.original_config_file = dict(
            sorted(self.original_conf_file.items())
        )

        self.file_path = file_path
        self.iter_index = 0

    def update_selector(self, short_name, selector):
        self.entries[short_name][self.SELECTOR] = selector

    def __iter__(self):
        return self

    def __next__(self):
        if self.iter_index == len(self.entries):
            self.iter_index = 0
            raise StopIteration

        key = list(self.entries.keys())[self.iter_index]
        self.iter_index = self.iter_index + 1
        return key, self.entries[key]

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, key):
        if isinstance(key, int):
            try:
                short_name = list(self.entries.keys())[key]
                return self.entries[short_name]
            except IndexError:
                raise IndexError(
                    "Index {} not found".format(key)
                )
        elif isinstance(key, str):
            if key not in self.entries:
                raise KeyError(
                    "Short name, {}, not found".format(key)
                )
            return self.entries[key]
        else:
            raise TypeError(
                "Index must be an int or str, not {}".format(
                    type(key).__name__
                )
            )

    def save_changes(self):
        self.write_entries_to_file(self.entries)

    def revert_changes(self):
        self.write_entries_to_file(self.original_conf_file)

    def write_entries_to_file(self, entries):
        max_short_name_len = max(len(x) for x in entries)
        padding_length = (
            max_short_name_len + self.SELECTOR_PADDING
        )

        with open(self.file_path, "w") as f:
            for short_name, entry in entries.items():
                line_format = (
                    "{:"
                    + str(padding_length)
                    + "}{}:{}:{}\n"
                )

                entry = line_format.format(
                    short_name,
                    entry[self.DOMAIN],
                    entry[self.SELECTOR],
                    entry[self.PRIVATE_KEY],
                )

                f.write(entry)
