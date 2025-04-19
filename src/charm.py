#!/usr/bin/env python3
# Copyright (c) 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOperatorCharm."""

import logging
import secrets

from ops import (
    CharmBase,
    ActionEvent,
    InstallEvent,
    StoredState,
    RelationJoinedEvent,
    ActiveStatus,
    BlockedStatus,
    WaitingStatus,
    main,
)

from exceptions import OpenLDAPOpsError
from openldap import OpenLDAPOps

logger = logging.getLogger()


class OpenLDAPOperatorCharm(CharmBase):
    """OpenLDAP Operator lifecycle events."""

    _stored = StoredState()

    def __init__(self, *args, **kwargs):
        """Init _stored attributes and interfaces, observe events."""
        super().__init__(*args, **kwargs)

        self._stored.set_default(
            domain=str(),
            organization_name=str(),
        )

        # self.sssd = SSSD(self, "sssd")

        event_handler_bindings = {
            self.on.install: self._on_install,
            self.on[
                "homedir-server-ipaddr"
            ].relation_joined: self._on_homedir_server_joined,
            self.on.get_admin_password_action: self._on_get_admin_password,
            self.on.get_sssd_binder_password_action: self._on_get_sssd_binder_password,
        }
        for event, handler in event_handler_bindings.items():
            self.framework.observe(event, handler)

    def _on_install(self, event: InstallEvent) -> None:
        """Perform installation operations."""

        admin_password = secrets.token_urlsafe(32)
        content = {"password": admin_password}
        secret = self.app.add_secret(content, label="admin-password")
        logger.debug(f"admin-password secret id: {secret.id}")

        sssd_binder_password = secrets.token_urlsafe(32)
        content = {"password": sssd_binder_password}
        secret = self.app.add_secret(content, label="sssd-binder-password")
        logger.debug(f"sssd-binder-password secret id: {secret.id}")

        self._domain = self.config.get("domain")
        self._organization_name = self.config.get("organization-name")

        try:
            self.unit.status = WaitingStatus("Installing OpenLDAP server...")
            OpenLDAPOps().install(
                base_dn=self._base_dn,
                domain=self._domain,
                organization_name=self._organization_name,
                admin_password=admin_password,
                sssd_binder_password=sssd_binder_password,
            )
            self.unit.status = ActiveStatus("OpenLDAP installed.")
            self.unit.status = ActiveStatus("")
        except OpenLDAPOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble installing OpenLDAP, please debug."
            )
            logger.debug(e)
            event.defer()
            return

    def _on_homedir_server_joined(self, event: RelationJoinedEvent) -> None:
        """Get the homedir server ip address and configure the maps for automount."""
        homedir_server_ipaddr = event.relation.data[event.unit]["ingress-address"]

        try:
            self.unit.status = WaitingStatus("Adding automount maps to ldap server...")
            OpenLDAPOps().configure_automount_maps(
                self._base_dn, self._admin_password, homedir_server_ipaddr
            )
            self.unit.status = ActiveStatus("Automount maps successfully added.")
            self.unit.status = ActiveStatus("")
        except OpenLDAPOpsError as e:
            self.unit.status = BlockedStatus(
                "Trouble adding automount maps to ldap, please debug."
            )
            logger.debug(e)
            event.defer()
            return

    def _on_get_admin_password(self, event: ActionEvent) -> None:
        """Return the ldap admin password."""
        event.set_results({"password": self._admin_password})

    def _on_get_sssd_binder_password(self, event: ActionEvent) -> None:
        """Return the ldap admin password."""
        event.set_results({"password": self._sssd_binder_password})

    @property
    def _admin_password(self) -> str:
        """Return the ldap admin_password from stored state."""
        secret = self.app.get_secret(label="admin-password")
        return secret.get_content()["password"]

    @property
    def _sssd_binder_password(self) -> str:
        """Return the sssd-binder password from stored state."""
        secret = self.app.get_secret(label="sssd-binder-password")
        return secret.get_content()["password"]

    @property
    def _base_dn(self) -> str:
        """Return the base_dn from the domain."""
        return f"dc={self._domain.split('.')[0]},dc={self._domain.split('.')[1]}"

    @property
    def _domain(self) -> str:
        """Return the ldap domain from stored state."""
        return self._stored.domain

    @_domain.setter
    def _domain(self, domain: str) -> None:
        """Set the domain in stored state."""
        self._stored.domain = domain

    @property
    def _organization_name(self) -> str:
        """Return the ldap organization name from stored state."""
        return self._stored.organization_name

    @_organization_name.setter
    def _organization_name(self, organization_name: str) -> None:
        """Set the organization name in stored state."""
        self._stored.organization_name = organization_name


if __name__ == "__main__":  # pragma: nocover
    main(OpenLDAPOperatorCharm)
