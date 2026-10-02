from collections.abc import Callable
from http import HTTPStatus
from urllib.parse import urlparse

import pytest
import requests
from selenium import webdriver
from testcontainers.core.container import Network

from fixtures import types
from fixtures.auth import (
    USER_ADMIN_EMAIL,
    USER_ADMIN_PASSWORD,
    assert_user_has_role,
    find_user_with_roles_by_email,
)
from fixtures.idp import perform_oidc_login
from fixtures.signoz import create_signoz

CLIENT_ID = "oidc.community.integration.test"


@pytest.fixture(name="signoz", scope="package")
def signoz_community(
    network: Network,
    zeus: types.TestContainerDocker,
    gateway: types.TestContainerDocker,
    sqlstore: types.TestContainerSQL,
    clickhouse: types.TestContainerClickhouse,
    request: pytest.FixtureRequest,
    pytestconfig: pytest.Config,
) -> types.SigNoz:
    """
    Community-binary SigNoz, used to verify OIDC login works with no
    enterprise license.
    """
    return create_signoz(
        network=network,
        zeus=zeus,
        gateway=gateway,
        sqlstore=sqlstore,
        clickhouse=clickhouse,
        request=request,
        pytestconfig=pytestconfig,
        cache_key="signoz-community-oidc",
        edition="community",
    )


def test_create_auth_domain(
    signoz: types.SigNoz,
    idp: types.TestContainerIDP,  # pylint: disable=unused-argument
    create_oidc_client: Callable[[str, str], None],
    get_oidc_settings: Callable[[str], dict],
    create_user_admin: Callable[[], None],  # pylint: disable=unused-argument
    get_token: Callable[[str, str], str],
) -> None:
    create_oidc_client(CLIENT_ID, "/api/v1/complete/oidc")
    settings = get_oidc_settings(CLIENT_ID)
    admin_token = get_token(USER_ADMIN_EMAIL, USER_ADMIN_PASSWORD)

    response = requests.post(
        signoz.self.host_configs["8080"].get("/api/v2/auth_domains"),
        json={
            "name": "oidc.community.integration.test",
            "enabled": True,
            "config": {
                "kind": "oidc",
                "spec": {
                    "clientId": settings["client_id"],
                    "clientSecret": settings["client_secret"],
                    "issuer": f"{idp.container.container_configs['6060'].get(urlparse(settings['issuer']).path)}",
                    "issuerAlias": settings["issuer"],
                    "getUserInfo": True,
                    "claimMapping": {
                        "email": "email",
                        "name": "name",
                        "groups": "groups",
                        "role": "signoz_role",
                    },
                },
            },
            "roleMapping": {
                "defaultRole": "VIEWER",
                "groupMappings": {
                    "signoz-admins": "ADMIN",
                    "signoz-editors": "EDITOR",
                },
                "useRoleAttribute": False,
            },
        },
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=2,
    )

    assert response.status_code == HTTPStatus.CREATED, response.text


def test_oidc_login_without_license(
    signoz: types.SigNoz,
    idp: types.TestContainerIDP,  # pylint: disable=unused-argument
    driver: webdriver.Chrome,
    create_user_idp: Callable[[str, str, bool, str, str], None],
    idp_login: Callable[[str, str], None],
    get_token: Callable[[str, str], str],
    get_session_context: Callable[[str], str],
) -> None:
    """
    OIDC login must work on the community binary with no license applied.
    """
    email = "viewer@oidc.community.integration.test"
    create_user_idp(email, "password123", True)

    perform_oidc_login(signoz, idp, driver, get_session_context, idp_login, email, "password123")

    admin_token = get_token(USER_ADMIN_EMAIL, USER_ADMIN_PASSWORD)
    found_user = find_user_with_roles_by_email(signoz, admin_token, email)
    assert_user_has_role(found_user, "signoz-viewer")


def test_oidc_login_group_role_mapping(
    signoz: types.SigNoz,
    idp: types.TestContainerIDP,
    driver: webdriver.Chrome,
    create_user_idp_with_groups: Callable[[str, str, bool, list[str]], None],
    idp_login: Callable[[str, str], None],
    get_token: Callable[[str, str], str],
    get_session_context: Callable[[str], str],
) -> None:
    """
    A user in a mapped Keycloak group gets the mapped SigNoz role.
    """
    email = "admin-group-user@oidc.community.integration.test"
    create_user_idp_with_groups(email, "password123", True, ["signoz-admins"])

    perform_oidc_login(signoz, idp, driver, get_session_context, idp_login, email, "password123")

    admin_token = get_token(USER_ADMIN_EMAIL, USER_ADMIN_PASSWORD)
    found_user = find_user_with_roles_by_email(signoz, admin_token, email)
    assert_user_has_role(found_user, "signoz-admin")


def test_oidc_login_unmapped_group_uses_default_role(
    signoz: types.SigNoz,
    idp: types.TestContainerIDP,
    driver: webdriver.Chrome,
    create_user_idp_with_groups: Callable[[str, str, bool, list[str]], None],
    idp_login: Callable[[str, str], None],
    get_token: Callable[[str, str], str],
    get_session_context: Callable[[str], str],
) -> None:
    email = "unmapped-group-user@oidc.community.integration.test"
    create_user_idp_with_groups(email, "password123", True, ["some-other-group"])

    perform_oidc_login(signoz, idp, driver, get_session_context, idp_login, email, "password123")

    admin_token = get_token(USER_ADMIN_EMAIL, USER_ADMIN_PASSWORD)
    found_user = find_user_with_roles_by_email(signoz, admin_token, email)
    assert_user_has_role(found_user, "signoz-viewer")
