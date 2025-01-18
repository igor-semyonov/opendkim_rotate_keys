import logging
import os

import requests

logger = logging.getLogger(__name__)

__all__ = ["DnsProvider", "LinodeDnsProvider"]


class DnsProvider:
    """DNS provider."""

    def create_txt_record(self, domain, selector, value):
        raise NotImplementedError()


class LinodeDnsProvider(DnsProvider):
    """DNS provider for Linode.

    Linode requires a domain ID when adding any DNS records. Rather than
    enumerating all domains on every request to create a TXT record in order
    to find the ID of the domain in use, all domains for the Linode account
    are cached in memory so that subsequent requests are faster. This opens
    the possibility of errors if the domain on Linode is deleted after its
    information has been cached.

    Full documentation on Linode API:
    https://www.linode.com/api/
    """

    api_key = ""
    #  api_url = "https://api.linode.com"
    api_url = "https://api.linode.com/v4/domains?page=1&page_size=100"

    def __init__(self):
        if "LINODE_API_KEY" not in os.environ:
            raise KeyError(
                "LINODE_API_KEY environment variable not set"
            )

        self.api_key = os.environ.get("LINODE_API_KEY")
        self.domains = {}

    def create_txt_record(
        self,
        domain: str,
        selector: str,
        value: str,
    ):
        if domain not in self.domains:
            raise KeyError(
                f"Domain {domain} not found in Linode"
            )

        url = f"https://api.linode.com/v4/domains/{self.domains[domain]}/records"

        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }

        payload = {
            "name": f"{selector}_domainkey",
            "type": "TXT",
            "target": value,
            "ttl_sec": 3600,
        }
        response = requests.post(
            url, json=payload, headers=headers
        )

    def get_records(self, domain: str):
        if domain not in self.domains.keys():
            raise f"{domain} not in domains {self.domains}"

        url = f"https://api.linode.com/v4/domains/{self.domains[domain]}/records"
        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def delete_txt_record(
        self,
        domain: str,
        record_id: int,
    ):
        if domain not in self.domains.keys():
            raise f"{domain} not in domains {self.domains}"

        url = f"https://api.linode.com/v4/domains/{self.domains[domain]}/records/{record_id}"

        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }

        response = requests.delete(url, headers=headers)
        return response.json()

    def get_domains(self):
        url = "https://api.linode.com/v4/domains"

        headers = {
            "accept": "application/json",
            "authorization": f"Bearer {self.api_key}",
        }

        response = requests.get(url, headers=headers)
        #  response.raise_for_status()
        response = response.json()

        for domain_spec in response["data"]:
            self.domains[domain_spec["domain"]] = (
                domain_spec["id"]
            )

        if len(self.domains) == 0:
            raise RuntimeError("No domains found on Linode")

    def send_request(self, data):
        headers = {
            "User-Agent": "opendkim_rotate_keys/1.0.0"
        }

        data["api_key"] = self.api_key

        r = requests.get(
            self.api_url, data=data, headers=headers
        ).text
        return r

        if len(r["ERRORARRAY"]) > 0:
            messages = []

            for error in r["ERRORARRAY"]:
                msg = "{} (code {})".format(
                    error["ERRORMESSAGE"],
                    error["ERRORCODE"],
                )
                messages.append(msg)

            raise RuntimeError(
                "Errors from Linode: {}".format(
                    ", ".join(messages)
                )
            )

        return r
