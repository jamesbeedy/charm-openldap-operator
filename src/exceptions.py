# Copyright (c) 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""exceptions.py"""


class IngressAddressUnavailableError(Exception):
    """Exception raised when the ingress address is unavailable."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]


class OpenLDAPOpsError(Exception):
    """Exception raised by openldap installer."""

    @property
    def message(self) -> str:
        """Return message passed as argument to exception."""
        return self.args[0]
