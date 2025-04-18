# Copyright 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOps."""

import logging
import subprocess

from pathlib import Path
from shutil import copy2
from textwrap import dedent

from exceptions import OpenLDAPOpsError
import charms.operator_libs_linux.v0.apt as apt

logger = logging.getLogger()


def _add_sssd_binder_user() -> None:
    """Add sssd-binder user."""

    ldifs = [
        "./src/templates/add-sssd-binder.ldif",
    ]
    for ldif in ldifs:
        try:
            subprocess.check_call(
                [
                    "ldapadd",
                    "-x",
                    "-D",
                    "cn=admin,dc=example,dc=com",
                    "-w",
                    "admin",
                    "-f",
                    ldif,
                ]
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise e


def _add_organizational_units() -> None:
    """Add organizational units to openldap."""

    ldifs = [
        "./src/templates/add-organizational-units.ldif",
    ]
    for ldif in ldifs:
        try:
            subprocess.check_call(
                [
                    "ldapadd",
                    "-x",
                    "-D",
                    "cn=admin,dc=example,dc=com",
                    "-w",
                    "admin",
                    "-f",
                    ldif,
                ]
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise e

def _add_slurm_users_group_and_user() -> None:
    """Add slurm users group and add a user."""

    ldifs = [
        "./src/templates/add-slurm-users-group.ldif",
        "./src/templates/add-user.ldif",
    ]
    for ldif in ldifs:
        try:
            subprocess.check_call(
                [
                    "ldapadd",
                    "-x",
                    "-D",
                    "cn=admin,dc=example,dc=com",
                    "-w",
                    "admin",
                    "-f",
                    ldif,
                ]
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise e

def _add_automount_home_map_entries() -> None:
    """Add automap home entries."""

    ldifs = [
        "./src/templates/add-automount-home-map-entries.ldif",
    ]
    for ldif in ldifs:
        try:
            subprocess.check_call(
                [
                    "ldapadd",
                    "-x",
                    "-D",
                    "cn=admin,dc=example,dc=com",
                    "-w",
                    "admin",
                    "-f",
                    ldif,
                ]
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise e

def _add_schemas() -> None:
    """Add schemas to openldap."""

    schemas = [
        "./src/templates/autofs-schema.ldif",
        "./src/templates/openssh-lpk.ldif",
    ]
    for schema_ldif in schemas:
        try:
            subprocess.check_call(
                ["ldapadd", "-Y", "EXTERNAL", "-H", "ldapi:///", "-f", schema_ldif]
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise e


def _modify_permissions() -> None:
    """Update permissions of the sssd-binder user."""
    try:
        subprocess.check_call(
            [
                "ldapmodify",
                "-Y",
                "EXTERNAL",
                "-H",
                "ldapi:///",
                "-f",
                "./src/templates/update-permissions.ldif",
            ]
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise e


def _restart_slapd() -> None:
    """Restart slapd."""
    try:
        subprocess.call(["systemctl", "restart", "slapd"])
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)


def _set_debconf_value(package, question, val_type, value) -> None:
    """Set debconf value."""
    debconf_line = f"{package} {question} {val_type} {value}\n"
    try:
        process = subprocess.Popen(
            ["debconf-set-selections"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # Ensures strings, not bytes
        )
        stdout, stderr = process.communicate(debconf_line)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    if process.returncode != 0:
        raise OpenLDAPOpsError(f"Failed to set debconf: {stderr.strip()}")


class OpenLDAPOps:
    """Facilitate openldap lifecycle ops."""

    def __init__(self):
        self._packages = ["ldap-utils", "slapd", "debconf-utils"]
        self._cert_dir = Path("/etc/ssl/ldap")
        self._cert_file = self._cert_dir / "ldap.crt"
        self._key_file = self._cert_dir / "ldap.key"
        self._ca_file = Path("/etc/ssl/certs/ca-certificates.crt")

    def install(self, admin_pw: str, domain: str, organization_name: str) -> None:
        """Install packages."""

        slapd_configs = [
            ("slapd", "slapd/internal/adminpw", "password", admin_pw),
            ("slapd", "slapd/internal/generated_adminpw", "password", admin_pw),
            ("slapd", "slapd/password1", "password", admin_pw),
            ("slapd", "slapd/password2", "password", admin_pw),
            ("slapd", "slapd/domain", "string", domain),
            ("slapd", "shared/organization", "string", organization_name),
            ("slapd", "slapd/backend", "select", "MDB"),
            ("slapd", "slapd/no_configuration", "boolean", "false"),
            ("slapd", "slapd/purge_database", "boolean", "true"),
            ("slapd", "slapd/move_old_database", "boolean", "true"),
            ("slapd", "slapd/allow_ldap_v2", "boolean", "false"),
        ]

        for pkg, question, val_type, value in slapd_configs:
            _set_debconf_value(pkg, question, val_type, value)

        try:
            apt.update()
            apt.add_package(self._packages)
        except apt.PackageNotFoundError as e:
            logger.error("package not found in package cache or on system")
            raise OpenLDAPOpsError(e)
        except apt.PackageError as e:
            msg = f"Could not install packages. Reason: {e.message}"
            logger.error(msg)
            raise OpenLDAPOpsError(msg)

        # Put the slapd config in place.
        copy2("./src/templates/slapd.default", "/etc/default/slapd")
        # Create certs for ldap server.
        self._create_certs(domain, organization_name)

        # Configure tls.
        self._configure_ldap_tls()
        _restart_slapd()

        # Add extra schemas.
        _add_schemas()
        # Add organizational units.
        _add_organizational_units()
        # Add sssd-binder user.
        _add_sssd_binder_user()
        # Add slurm-users group and a user.
        _add_slurm_users_group_and_user()
        # Add automount home entries.
        _add_automount_home_map_entries()
        # Update permissions.
        _modify_permissions()

    def _create_certs(self, domain: str, organization_name: str) -> None:
        """Create certs for ldap."""

        self._cert_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-x509",
                    "-nodes",
                    "-days",
                    "365",
                    "-subj",
                    f"/C=US/ST=State/L=City/O={organization_name}/CN={domain}",
                    "-out",
                    f"{self._cert_file}",
                    "-keyout",
                    f"{self._key_file}",
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        try:
            subprocess.run(
                [
                    "chown",
                    "openldap:openldap",
                    f"{self._cert_file}",
                    f"{self._key_file}",
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        try:
            subprocess.run(["chmod", "600", f"{self._key_file}"], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

    def _configure_ldap_tls(self) -> None:
        """Configure ldap with the certs."""

        ldif = dedent(
            f"""\
            dn: cn=config
            changetype: modify
            replace: olcTLSCertificateFile
            olcTLSCertificateFile: {self._cert_file}
            -
            replace: olcTLSCertificateKeyFile
            olcTLSCertificateKeyFile: {self._key_file}
            -
            replace: olcTLSCACertificateFile
            olcTLSCACertificateFile: {self._ca_file}
            """
        )

        try:
            process = subprocess.Popen(
                ["ldapmodify", "-Y", "EXTERNAL", "-H", "ldapi:///"],
                stdin=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = process.communicate(ldif)
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        if process.returncode != 0:
            raise OpenLDAPOpsError(f"ldapmodify failed:\n{stderr}")
