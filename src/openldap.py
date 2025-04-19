# Copyright 2025 Vantage Compute Corporation
# See LICENSE file for licensing details.

"""OpenLDAPOps."""

import logging
import subprocess

from pathlib import Path
from shutil import copy2
from string import Template
from typing import Literal


from exceptions import OpenLDAPOpsError
import charms.operator_libs_linux.v0.apt as apt


logger = logging.getLogger()


_CERT_DIR = Path("/etc/ssl/ldap")
_CERT_FILE = _CERT_DIR / "ldap.crt"
_KEY_FILE = _CERT_DIR / "ldap.key"
_CA_FILE = Path("/etc/ssl/certs/ca-certificates.crt")


def _create_certs(domain: str, organization_name: str) -> None:
    """Create certs for ldap."""

    _CERT_DIR.mkdir(parents=True, exist_ok=True)

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
                f"{_CERT_FILE}",
                "-keyout",
                f"{_KEY_FILE}",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    try:
        subprocess.run(
            ["chown", "openldap:openldap", f"{_CERT_FILE}", f"{_KEY_FILE}"], check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    try:
        subprocess.run(["chmod", "600", f"{_KEY_FILE}"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)


def _update_ldap_tls_config(base_dn: str, admin_password: str) -> None:
    """Add cert, key, and ca to ldap config."""

    ldif_template_path = Path("./templates/update-tls-config.ldif")
    ldif_template = Template(ldif_template_path.read_text())
    ldif = ldif_template.substitute(
        cert_file=_CERT_FILE, key_file=_KEY_FILE, ca_file=_CA_FILE
    )
    _ldap("modify", base_dn, admin_password, ldif)


def _add_sssd_binder_user(
    base_dn: str, admin_password: str, sssd_binder_password: str
) -> None:
    """Add sssd-binder user."""
    try:
        p = subprocess.Popen(
            ["slappasswd", "-h", "{SSHA}", "-s", sssd_binder_password],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = p.communicate()
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

    sssd_binder_password_hash = stdout.strip()

    ldif_template_path = Path("./templates/add-sssd-binder.ldif")
    ldif_template = Template(ldif_template_path.read_text())
    ldif = ldif_template.substitute(
        base_dn=base_dn,
        sssd_binder_password_hash=sssd_binder_password_hash,
    )
    logger.debug(ldif)
    _ldap("add", base_dn, admin_password, ldif)


def _add_organizational_units(base_dn: str, admin_password: str) -> None:
    """Add organizational units to openldap."""

    ldif_template_path = Path("./templates/add-organizational-units.ldif")
    ldif_template = Template(ldif_template_path.read_text())
    ldif = ldif_template.substitute(base_dn=base_dn)
    logger.debug(ldif)
    _ldap("add", base_dn, admin_password, ldif)


def _add_slurm_users_group_and_user(base_dn: str, admin_password: str) -> None:
    """Add slurm users group and add a user."""

    ldif_templates = [
        Path("./templates/add-slurm-users-group.ldif"),
        Path("./templates/add-user.ldif"),
    ]
    for ldif_template_path in ldif_templates:
        ldif_template = Template(ldif_template_path.read_text())
        ldif = ldif_template.substitute(base_dn=base_dn)
        logger.debug(ldif)
        _ldap("add", base_dn, admin_password, ldif)


def _add_automount_home_map_entries(
    base_dn: str, admin_password: str, homedir_server_ipaddr: str
) -> None:
    """Add automap home entries."""

    ldif_template_path = Path("./templates/add-automount-home-map-entries.ldif")
    ldif_template = Template(ldif_template_path.read_text())
    ldif = ldif_template.substitute(
        base_dn=base_dn, homedir_server_ipaddr=homedir_server_ipaddr
    )
    logger.debug(ldif)
    _ldap("add", base_dn, admin_password, ldif)


def _add_schemas() -> None:
    """Add schemas to openldap."""

    schemas = [
        Path("./templates/autofs-schema.ldif"),
        Path("./templates/openssh-lpk-schema.ldif"),
    ]
    for schema_ldif in schemas:
        try:
            process = subprocess.Popen(
                ["ldapadd", "-Y", "EXTERNAL", "-v", "-H", "ldapi:///"],
                stdin=subprocess.PIPE,
                text=True,
            )
            ldif = schema_ldif.read_text()
            logger.debug(ldif)
            stdout, stderr = process.communicate(ldif)
        except subprocess.CalledProcessError as e:
            logger.error(e)
            raise OpenLDAPOpsError(e)

        if process.returncode != 0:
            raise OpenLDAPOpsError(f"Adding schema failed:\n{stderr}")


def _assign_sssd_binder_user_read_only_permissions(
    base_dn: str, admin_password: str
) -> None:
    """Assign read only permissions to the sssd-binder user."""
    ldif_template_path = Path("./templates/update-permissions.ldif")
    ldif_template = Template(ldif_template_path.read_text())
    ldif = ldif_template.substitute(base_dn=base_dn)
    logger.debug(ldif)
    _ldap("modify", base_dn, admin_password, ldif)


def _ldap(
    cmd: Literal["add", "modify"], base_dn: str, admin_password: str, ldif: str
) -> None:
    """Add or modify an ldap mapping."""

    try:
        process = subprocess.Popen(
            [
                f"ldap{cmd}",
                "-x",
                "-D",
                f"cn=admin,{base_dn}",
                "-v",
                "-w",
                admin_password,
            ],
            stdin=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(ldif)
    except subprocess.CalledProcessError as e:
        logger.error(e)
        raise OpenLDAPOpsError(e)

        if process.returncode != 0:
            raise OpenLDAPOpsError(f"ldap{cmd} failed:\n{stderr}")


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

    def install(
        self,
        base_dn: str,
        domain: str,
        organization_name: str,
        admin_password: str,
        sssd_binder_password: str,
    ) -> None:
        """Install packages."""

        slapd_non_interactive_configs = [
            ("slapd", "slapd/internal/adminpw", "password", admin_password),
            ("slapd", "slapd/internal/generated_adminpw", "password", admin_password),
            ("slapd", "slapd/password1", "password", admin_password),
            ("slapd", "slapd/password2", "password", admin_password),
            ("slapd", "slapd/domain", "string", domain),
            ("slapd", "shared/organization", "string", organization_name),
            ("slapd", "slapd/backend", "select", "MDB"),
            ("slapd", "slapd/no_configuration", "boolean", "false"),
            ("slapd", "slapd/purge_database", "boolean", "true"),
            ("slapd", "slapd/move_old_database", "boolean", "true"),
            ("slapd", "slapd/allow_ldap_v2", "boolean", "false"),
        ]

        for pkg, question, val_type, value in slapd_non_interactive_configs:
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
        copy2("./templates/slapd.default", "/etc/default/slapd")

        # Create certs for ldap server and configure tls.
        _create_certs(domain, organization_name)
        _update_ldap_tls_config(base_dn, admin_password)
        _restart_slapd()

        # Add extra schemas.
        _add_schemas()

        # Add organizational units.
        _add_organizational_units(base_dn, admin_password)

        # Add sssd-binder user and assign permissions.
        _add_sssd_binder_user(base_dn, admin_password, sssd_binder_password)
        _assign_sssd_binder_user_read_only_permissions(base_dn, admin_password)

        # Add slurm-users group and a user.
        _add_slurm_users_group_and_user(base_dn, admin_password)

    def configure_automount_maps(
        self, base_dn: str, admin_password: str, homedir_server_ipaddr: str
    ) -> None:
        """Add automount home entries."""
        _add_automount_home_map_entries(base_dn, admin_password, homedir_server_ipaddr)
