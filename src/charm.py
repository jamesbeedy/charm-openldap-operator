#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOperatorCharm."""

import logging

from ops import (
    CharmBase,
    ActionEvent,
    InstallEvent,
    StartEvent,
    ConfigChangedEvent,
    ActiveStatus,
    BlockedStatus,
    WaitingStatus,
    main,
)

from exceptions import IngressAddressUnavailableError, OpenLDAPOpsError
from openldap import OpenLDAPOps

logger = logging.getLogger()


class OpenLDAPOperatorCharm(CharmBase):
    """OpenLDAP Operator lifecycle events."""

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on.start: self._on_start,
            self.on.config_changed: self._on_config_changed,
            self.on.get_admin_password_action: self._on_get_admin_password,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _on_install(self, event: InstallEvent) -> None:
        """Perform installation operations."""

        admin_pw = self.config.get("admin-password")
        domain = self.config.get("domain")
        organization_name = self.config.get("organization-name")

        try:
            self.unit.status = WaitingStatus("Installing OpenLDAP server...")
            OpenLDAPOps().install(admin_pw, domain, organization_name)
            self.unit.status = ActiveStatus("OpenLDAP installed.")
            self.unit.status = ActiveStatus("")
        except OpenLDAPOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble installing OpenLDAP, please debug."
            )
            logger.debug(e)
            event.defer()
            return

    def _on_start(self, event: StartEvent) -> None:
        """Start hook."""
        pass

    def _on_config_changed(self, event: ConfigChangedEvent) -> None:
        """Perform config-changed operations."""
        pass

    @property
    def _ingress_address(self) -> str:
        """Return the ingress_address from the peer relation if it exists."""
        if (peer_binding := self.model.get_binding("jupyterhub-peer")) is not None:
            ingress_address = f"{peer_binding.network.ingress_address}"
            logger.debug(f"ingress_address: {ingress_address}")
            return ingress_address
        raise IngressAddressUnavailableError("Ingress address unavailable")

    def _on_get_admin_password(self, event: ActionEvent) -> None:
        """Return the ldap admin password."""
        event.set_results({"password": "rrrrattsss"})


if __name__ == "__main__":  # pragma: nocover
    main(OpenLDAPOperatorCharm)
