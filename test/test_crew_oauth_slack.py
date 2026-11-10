"""Crew-owned OAuth for Slack's hosted MCP server (``mcp.slack.com/mcp``).

Slack is a pre-registered client with a secret: PKCE S256 plus
``client_secret_post``, the one method its MCP authorization server lists. Errors
arrive as a 200 with ``{"ok": false}``, refresh tokens rotate and are single-use,
and ``auth.revoke`` takes the access token and answers in the body.
"""

from __future__ import annotations

import json
import logging
import time
import types
import urllib.parse

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from kas_agents_helpers import _spec

from kiro_crew.acp import kas_agents
from kiro_crew.connections import crew_oauth, crew_oauth_proxy, registry
from kiro_crew.connections.crew_oauth import CrewOAuthError, Tokens, TokenStore
from kiro_crew.secrets import SecretVault

SLUG = "slack"
SESSION = "dashboard_chat-crew-oauth-slack"
REDIRECT = "http://localhost:48106/callback"
SLACK_URL = "https://mcp.slack.com/mcp"


@pytest.fixture(autouse=True)
def _pinned_modules(_floor_monkeypatch):
    """The code under test imports these at call time; pin them to this file's."""
    import sys

    import kiro_crew.connections as connections_pkg

    for name, module in (("crew_oauth", crew_oauth), ("crew_oauth_proxy", crew_oauth_proxy)):
        _floor_monkeypatch.setitem(sys.modules, f"kiro_crew.connections.{name}", module)
        _floor_monkeypatch.setattr(connections_pkg, name, module, raising=False)
    crew_oauth._refresh_locks.clear()
    crew_oauth_proxy._bridges.clear()
    _floor_monkeypatch.setenv("KIROCREW_BOUND_PORT", "8765")
    _floor_monkeypatch.delenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_ID", raising=False)
    _floor_monkeypatch.delenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_SECRET", raising=False)
    yield
    crew_oauth_proxy._bridges.clear()


def _client(client_id="123.456"):
    return types.SimpleNamespace(client_id=client_id, client_secret="sec")


# --- registry and consent URL -----------------------------------------------------


def test_slack_is_a_confidential_client_on_its_localhost_port():
    provider = registry.get_provider(SLUG)
    assert SLUG in crew_oauth.SUPPORTED_SLUGS and SLUG not in crew_oauth.DCR_SLUGS
    assert provider["mcp_url"] == "https://mcp.slack.com/mcp"
    assert provider["auth"]["confidential"] is True
    assert registry.redirect_uri(provider) == REDIRECT


def test_the_consent_url_is_slacks_user_token_page_with_pkce():
    url = crew_oauth.authorize_url(SLUG, "123.456", REDIRECT, "st", "ch")
    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query))
    assert (parts.scheme, parts.netloc, parts.path) == (
        "https",
        "slack.com",
        "/oauth/v2_user/authorize",
    )
    assert query["scope"].split() == list(registry.get_provider(SLUG)["recommended_scopes"])
    assert query["code_challenge_method"] == "S256" and query["code_challenge"] == "ch"
    assert query["redirect_uri"] == REDIRECT and query["response_type"] == "code"
    # Desktop redirects may not ask for bot scopes, and none are sent.
    assert "user_scope" not in query
    from kiro_crew.security import oauth_url_contains_credential

    vetted = crew_oauth.authorize_url(SLUG, "123.456", REDIRECT, "A" * 43, "A" * 43)
    assert oauth_url_contains_credential(vetted) is False


_SLACK_USER_QUERY = (
    "?response_type=code&client_id=3336676.569200954261"
    "&redirect_uri=http%3A%2F%2Flocalhost%3A48106%2Fcallback"
    "&scope=search%3Aread.public+channels%3Ahistory"
    "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    "&code_challenge_method=S256"
    "&state=" + ("Kp7mQ2xR" * 12)
)


def test_the_banner_gate_admits_a_high_entropy_state_at_slacks_user_consent_page():
    """Without the exact pair the PKCE values read as a credential and sign-in fails closed."""
    from kiro_crew.security import oauth_url_contains_credential

    url = "https://slack.com/oauth/v2_user/authorize" + _SLACK_USER_QUERY
    assert oauth_url_contains_credential(url) is False


def test_the_banner_gate_still_rejects_it_at_a_neighbouring_path():
    from kiro_crew.security import oauth_url_contains_credential

    url = "https://slack.com/oauth/v2_user/authorize/x" + _SLACK_USER_QUERY
    assert oauth_url_contains_credential(url) is True


# --- the client: id AND secret, from OAuth Apps ------------------------------------


def test_crew_refuses_a_slack_client_without_its_secret(tmp_path, monkeypatch):
    from kiro_crew.config import loader, paths

    config = {"connections": {"oauth_clients": {SLUG: {"client_id": "123.456"}}}}
    monkeypatch.setattr(loader, "read_config_for_update", lambda: config)
    monkeypatch.setattr(paths, "config_dir", lambda: tmp_path)
    with pytest.raises(CrewOAuthError) as err:
        crew_oauth._client(SLUG)
    assert err.value.code == "client_not_configured"
    monkeypatch.setenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_SECRET", "sec")
    resolved = crew_oauth._client(SLUG)
    assert (resolved.client_id, resolved.client_secret) == ("123.456", "sec")
    assert resolved.redirect_uri == REDIRECT


def test_the_sign_in_refuses_a_resolved_client_that_has_no_secret(tmp_path, monkeypatch):
    """The sign-in's own check, apart from the resolver's: no secret, no sign-in."""
    from kiro_crew.config import loader, paths
    from kiro_crew.connections import oauth_clients

    monkeypatch.setattr(loader, "read_config_for_update", lambda: {})
    monkeypatch.setattr(paths, "config_dir", lambda: tmp_path)
    monkeypatch.setattr(
        oauth_clients,
        "resolve_oauth_client",
        lambda *a, **k: oauth_clients.ResolvedOAuthClient(
            SLUG, "123.456", "config", None, None, REDIRECT
        ),
    )
    with pytest.raises(CrewOAuthError) as err:
        crew_oauth._client(SLUG)
    assert err.value.code == "client_not_configured"


# --- token endpoint ---------------------------------------------------------------


def _slack(seen: list, token_answer: dict, revoke_answer: dict | str | None = None):
    async def _token(request):
        seen.append(("token", dict(await request.post())))
        return web.json_response(token_answer)

    async def _revoke(request):
        seen.append(("revoke", dict(await request.post())))
        if isinstance(revoke_answer, str):
            return web.Response(text=revoke_answer)
        return web.json_response(revoke_answer or {"ok": True, "revoked": True})

    app = web.Application()
    app.router.add_post("/api/oauth.v2.user.access", _token)
    app.router.add_post("/api/auth.revoke", _revoke)
    return app


async def _serve(monkeypatch, seen, token_answer=None, revoke_answer=None):
    server = TestServer(_slack(seen, token_answer or {"ok": True}, revoke_answer))
    await server.start_server()
    base = str(server.make_url(""))
    monkeypatch.setitem(
        crew_oauth._ENDPOINTS,
        SLUG,
        {
            **crew_oauth._ENDPOINTS[SLUG],
            "token": f"{base}/api/oauth.v2.user.access",
            "revoke": f"{base}/api/auth.revoke",
        },
    )
    return server


async def _swap(tmp_path, monkeypatch, answer, client):
    seen: list = []
    server = await _serve(monkeypatch, seen, answer)
    store = TokenStore(SecretVault(tmp_path))
    sign_in = crew_oauth.SignIn(SLUG)
    sign_in._client, sign_in._redirect = client, REDIRECT
    sign_in._done.set_result("the-code")
    try:
        await sign_in.finish(store)
    finally:
        await server.close()
    return seen, store, sign_in


@pytest.mark.asyncio
async def test_the_code_swap_sends_the_secret_and_the_verifier(tmp_path, monkeypatch):
    answer = {
        "ok": True,
        "access_token": "xoxe.xoxp-1",
        "refresh_token": "xoxe-1-r1",
        "expires_in": 43200,
        "token_type": "user",
        "authed_user": {"id": "U1", "scope": "search:read.public"},
    }
    seen, store, sign_in = await _swap(tmp_path, monkeypatch, answer, _client())
    form = seen[0][1]
    assert form == {
        "grant_type": "authorization_code",
        "client_id": "123.456",
        "client_secret": "sec",
        "code": "the-code",
        "redirect_uri": REDIRECT,
        "code_verifier": sign_in._verifier,
    }
    held = store.read(SLUG)
    assert held is not None
    assert (held[0].access, held[0].refresh, held[0].client) == (
        "xoxe.xoxp-1",
        "xoxe-1-r1",
        "123.456",
    )
    assert held[0].expires_at is not None and held[0].expires_at > time.time() + 43000


@pytest.mark.asyncio
async def test_slacks_200_ok_false_is_a_failed_swap_that_stores_nothing(tmp_path, monkeypatch):
    with pytest.raises(CrewOAuthError) as err:
        await _swap(tmp_path, monkeypatch, {"ok": False, "error": "invalid_code"}, _client())
    assert err.value.code == "invalid_code"
    assert TokenStore(SecretVault(tmp_path)).read(SLUG) is None


@pytest.mark.asyncio
async def test_a_refresh_rotates_the_single_use_refresh_token(tmp_path, monkeypatch):
    seen: list = []
    answer = {"ok": True, "access_token": "a2", "refresh_token": "r2", "expires_in": 43200}
    server = await _serve(monkeypatch, seen, answer)
    monkeypatch.setattr(crew_oauth, "_client", lambda s: _client())
    store = TokenStore(SecretVault(tmp_path))
    store.replace(SLUG, Tokens("a1", "r1", time.time() - 10, "", None, "123.456"))
    try:
        assert await crew_oauth.access_token(SLUG, store=store) == "a2"
    finally:
        await server.close()
    assert seen[0][1] == {
        "grant_type": "refresh_token",
        "refresh_token": "r1",
        "client_id": "123.456",
        "client_secret": "sec",
    }
    held = store.read(SLUG)
    assert held is not None and (held[0].access, held[0].refresh) == ("a2", "r2")
    assert held[0].client == "123.456"


@pytest.mark.asyncio
async def test_a_dead_refresh_token_asks_for_a_reconnect_and_keeps_the_pair(tmp_path, monkeypatch):
    seen: list = []
    server = await _serve(monkeypatch, seen, {"ok": False, "error": "invalid_refresh_token"})
    monkeypatch.setattr(crew_oauth, "_client", lambda s: _client())
    store = TokenStore(SecretVault(tmp_path))
    store.replace(SLUG, Tokens("a1", "r1", time.time() - 10, ""))
    try:
        with pytest.raises(CrewOAuthError) as err:
            await crew_oauth.access_token(SLUG, store=store)
    finally:
        await server.close()
    assert err.value.code == "needs_auth"
    assert store.read(SLUG) is not None


# --- Disconnect -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_revokes_the_access_token(tmp_path, monkeypatch):
    seen: list = []
    server = await _serve(monkeypatch, seen)

    def _gone(slug):
        raise CrewOAuthError("client_not_configured")

    # The revoke takes the token alone: a removed OAuth Apps record never blocks it.
    monkeypatch.setattr(crew_oauth, "_client", _gone)
    store = TokenStore(SecretVault(tmp_path))
    store.replace(SLUG, Tokens("a1", "r1", None, ""))
    try:
        result = await crew_oauth.disconnect(SLUG, store=store)
    finally:
        await server.close()
    assert result == {"removed": True, "revoked": True}
    assert seen == [("revoke", {"token": "a1"})]
    assert not store.present(SLUG)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [{"ok": False, "error": "token_expired"}, {"ok": True, "revoked": False}, "not json"],
    ids=["ok-false", "revoked-false", "non-json"],
)
async def test_a_200_that_says_not_revoked_is_reported_and_still_deletes(
    tmp_path, monkeypatch, answer
):
    seen: list = []
    server = await _serve(monkeypatch, seen, revoke_answer=answer)
    store = TokenStore(SecretVault(tmp_path))
    store.replace(SLUG, Tokens("a1", "r1", None, ""))
    try:
        result = await crew_oauth.disconnect(SLUG, store=store)
    finally:
        await server.close()
    assert result == {"removed": True, "revoked": False}
    assert not store.present(SLUG)


# --- custody: the vault, never a log, a spec or the session ------------------------


@pytest.mark.asyncio
async def test_the_pair_lives_only_in_the_vault(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    answer = {"ok": True, "access_token": "xoxp-SECRET-A", "refresh_token": "xoxe-SECRET-R"}
    _, store, _ = await _swap(tmp_path, monkeypatch, answer, _client())
    crew_oauth._audit("connections_crew_oauth_sign_in", "ok", SLUG)
    assert "SECRET" not in caplog.text
    # Encrypted at rest: no file under the data home carries either token.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"SECRET" not in path.read_bytes(), path
    assert store.present(SLUG)


def test_the_kas_projection_carries_the_bridge_not_the_client_or_token(tmp_path, monkeypatch):
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
    monkeypatch.setattr(crew_oauth, "enabled", lambda: True)
    monkeypatch.setattr(crew_oauth, "_chat_backend_bridged", lambda: True)
    url = registry.get_provider(SLUG)["mcp_url"]
    spec = _spec(
        tools=[f"@{SLUG}"],
        allowedTools=[f"@{SLUG}"],
        mcpServers={SLUG: {"url": url, "oauth": {"clientId": "123.456"}}},
    )
    out = kas_agents.to_client_custom_agent("kirocrew", spec, "p", session_key=SESSION)
    entry = out["mcpServers"][SLUG]
    assert "url" not in entry and "oauth" not in entry
    assert url not in json.dumps(out) and "123.456" not in json.dumps(out)
    assert crew_oauth_proxy.is_connection_server(SESSION, SLUG)


# --- which entry is Slack's, and what a rebuild keeps -------------------------------


def _url_variants(url: str) -> list[str]:
    """The two spellings the card still owns: one more trailing slash, other letter case."""
    return [url + "/", url.upper()]


def test_no_client_is_bound_and_no_sign_in_is_routed_at_a_variant_url():
    """The card owns a row at a trailing-slash or letter-case variant; nothing else does.

    ``provider_for_server`` binds the operator's client and ``routed_slug`` sends a
    sign-in to Crew, so both refuse every URL that is not the registry's exactly,
    for every pre-registered provider. The card's Connect writes the registry URL
    onto the row first, and only then is the row the provider's.
    """
    from kiro_crew.connections.oauth_clients import provider_for_server
    from kiro_crew.connections.registry import is_preregistered

    slugs = [p["slug"] for p in registry.get_all_registry_providers() if is_preregistered(p)]
    assert SLUG in slugs and "github" in slugs
    for slug in slugs:
        url = registry.get_provider(slug)["mcp_url"]
        assert provider_for_server(slug, {"url": url})["slug"] == slug
        for variant in _url_variants(url):
            assert provider_for_server(slug, {"url": variant}) is None, (slug, variant)
            assert crew_oauth.routed_slug(slug, {"url": variant}, provider_for_server) == "", (
                slug,
                variant,
            )


def _owner_slack(
    monkeypatch, *, app_saved=False, card_grant=False, owner_grant=True, recorded=True
):
    """An owner-added ``slack`` server at Slack's URL, preview on, chats on KAS.

    ``app_saved``: a Slack app under Settings -> OAuth Apps. ``card_grant``: Crew
    holds a grant under the card's slug. ``owner_grant``: Crew holds one under the
    owner key. ``recorded``: the sealed owner record names the server.
    """
    import kiro_crew.config.loader as loader
    from kiro_crew.connections.owner_servers import CONFIG_ROOT_KEY, CONFIG_SERVERS_KEY

    owner_key = crew_oauth.custom_key(SLUG, SLACK_URL)
    root: dict = {}
    if recorded:
        root[CONFIG_SERVERS_KEY] = {SLUG: {"url": SLACK_URL}}
    if app_saved:
        root["oauth_clients"] = {SLUG: {"client_id": "123.456"}}
        monkeypatch.setenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_SECRET", "sec")
    held = {owner_key} if owner_grant else set()
    if card_grant:
        held.add(SLUG)
    monkeypatch.setattr(loader, "read_config_for_update", lambda: {CONFIG_ROOT_KEY: root})
    monkeypatch.setattr(crew_oauth, "holds_grant", lambda slug: slug in held)
    monkeypatch.setattr(crew_oauth, "enabled", lambda: True)
    monkeypatch.setattr(crew_oauth, "_chat_backend", lambda: "kas")
    return owner_key


def _owner_sign_in_flag() -> object:
    from kiro_crew.dashboard.handlers import mcp_probe

    rows = [{"name": SLUG, "url": SLACK_URL}]
    mcp_probe._annotate_owner_sign_in(rows)
    return rows[0].get("ownerSignIn")


def test_an_owner_added_slack_server_keeps_its_own_path_while_the_card_has_no_app(monkeypatch):
    """No Slack app saved and no grant under the card: the owner's server is as before.

    Its row keeps the in-place Sign in, that sign-in goes to Crew with the preview
    on, and a session reads the grant Crew holds under the owner key.
    """
    from kiro_crew.connections.oauth_clients import provider_for_server
    from kiro_crew.connections.owner_servers import is_signable_name

    owner_key = _owner_slack(monkeypatch)
    entry = {"url": SLACK_URL}

    assert is_signable_name(SLUG)
    assert _owner_sign_in_flag() is True
    assert crew_oauth.signs_in_custom(entry)
    assert crew_oauth.routed_slug(SLUG, entry, provider_for_server, backend="kas") == owner_key


@pytest.mark.parametrize("state", [{"app_saved": True}, {"card_grant": True}], ids=["app", "grant"])
def test_the_card_owns_an_owner_added_slack_server_once_it_has_an_app_or_a_grant(
    monkeypatch, state
):
    """A saved Slack app, or a grant under the card's slug: the card owns the entry.

    The owner key is not used, the row loses its own Sign in, and the owner-server
    sign-in refuses the registry URL again.
    """
    from kiro_crew.connections.oauth_clients import provider_for_server
    from kiro_crew.connections.owner_servers import is_signable_name

    _owner_slack(monkeypatch, **state)
    entry = {"url": SLACK_URL}

    assert not is_signable_name(SLUG)
    assert _owner_sign_in_flag() is False
    assert not crew_oauth.signs_in_custom(entry)
    assert crew_oauth._custom_slug(SLUG, entry) == ""
    assert crew_oauth.routed_slug(SLUG, entry, provider_for_server, backend="kas") == SLUG


def test_only_the_owners_recorded_slack_server_is_left_to_its_own_path(monkeypatch):
    """A ``slack`` entry the owner did not record never reaches the owner path.

    It has no in-place Sign in and is routed to the card's slug, whatever grant
    sits under the key its name and url would make. The same holds for an entry
    the owner recorded at another url than the one in the spec.
    """
    from kiro_crew.connections.oauth_clients import provider_for_server

    owner_key = _owner_slack(monkeypatch, recorded=False)
    entry = {"url": SLACK_URL}

    assert _owner_sign_in_flag() is False
    assert crew_oauth._custom_slug(SLUG, entry) == ""
    assert crew_oauth.routed_slug(SLUG, entry, provider_for_server, backend="kas") == SLUG

    _owner_slack(monkeypatch)
    moved = {"url": SLACK_URL + "x"}
    monkeypatch.setattr(crew_oauth, "holds_grant", lambda slug: slug != SLUG)
    assert crew_oauth.routed_slug(SLUG, moved, provider_for_server, backend="kas") == ""
    assert owner_key != crew_oauth.custom_key(SLUG, SLACK_URL + "x")


def test_a_card_that_never_keeps_a_users_client_never_yields(monkeypatch):
    """The rule is Slack's: GitHub's card, as unconfigured as Slack's, keeps its name."""
    import kiro_crew.config.loader as loader
    from kiro_crew.connections.owner_servers import card_yields, is_signable_name

    monkeypatch.setattr(loader, "read_config_for_update", lambda: {})
    monkeypatch.setattr(crew_oauth, "holds_grant", lambda slug: False)

    assert card_yields(registry.get_provider(SLUG))
    assert not card_yields(registry.get_provider("github"))
    assert not card_yields(registry.get_provider("notion"))
    assert not is_signable_name("github") and not is_signable_name("notion")

    monkeypatch.setattr(crew_oauth, "holds_grant", lambda slug: None)
    assert not card_yields(registry.get_provider(SLUG))


MINE_NO_SECRET = {"clientId": "mine", "redirectUri": "http://localhost:3118/callback"}
MINE_WITH_SECRET = {**MINE_NO_SECRET, "clientSecret": "my-own-secret"}


def _rebuilt_slack_entry(tmp_path, monkeypatch, mine, *, recorded=False) -> tuple[dict, dict]:
    """Run the real rebuild; return the ``slack`` entry in the spec and in the user's file.

    The dashboard store owns the ``slack`` entry and carries the user's own client;
    the previous spec carries an operator-projected one. ``recorded`` writes the
    sealed owner record for the entry, as the dashboard's add does.
    """
    from kiro_crew import agent as agent_mod
    from kiro_crew.apps import bridges

    project = tmp_path / "project" / "agents"
    project.mkdir(parents=True)
    (project / "defaults.json").write_text(json.dumps({"name": "kirocrew"}), encoding="utf-8")
    (project / "prompt.md").write_text("prompt", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("KIROCREW_PROJECT_DIR", str(tmp_path / "project"))
    monkeypatch.setenv("KIROCREW_HOME", str(home))
    (home / "mcp.json").write_text(
        json.dumps({"mcpServers": {SLUG: {"url": SLACK_URL, "oauth": dict(mine)}}}),
        encoding="utf-8",
    )
    if recorded:
        record = {"connections": {"owner_mcp_servers": {SLUG: {"url": SLACK_URL}}}}
        (home / "config.json").write_text(json.dumps(record), encoding="utf-8")
    kiro_dir = tmp_path / ".kiro" / "agents"
    kiro_dir.mkdir(parents=True)
    spec_path = kiro_dir / "kirocrew.json"
    projected = {"clientId": "op", "clientSecret": "op-secret", "redirectUri": "r"}
    spec_path.write_text(
        json.dumps({"mcpServers": {SLUG: {"url": SLACK_URL, "oauth": projected}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(agent_mod, "KIRO_AGENTS_DIR", kiro_dir)
    monkeypatch.setattr(agent_mod, "_KIRO_MCP_JSON", tmp_path / "absent-kiro.json")
    monkeypatch.setattr(agent_mod, "_CC_MCP_JSON", tmp_path / "absent-cc.json")
    monkeypatch.setattr(bridges, "_mcp_json_path", lambda: spec_path)

    agent_mod.rebuild_agent_config(refresh_forks=False)

    written = json.loads(spec_path.read_text(encoding="utf-8"))["mcpServers"][SLUG]
    stored = json.loads((home / "mcp.json").read_text(encoding="utf-8"))["mcpServers"][SLUG]
    return written, stored


@pytest.mark.parametrize("mine", [MINE_NO_SECRET, MINE_WITH_SECRET], ids=["no-secret", "secret"])
def test_a_rebuild_with_no_oauth_apps_record_keeps_the_client_the_user_wrote(
    tmp_path, monkeypatch, mine
):
    """Through the real rebuild, preview off: kiro-cli keeps the user's own Slack client.

    With no OAuth Apps record the operator's projection goes and the user's client,
    as written, comes back.
    """
    written, stored = _rebuilt_slack_entry(tmp_path, monkeypatch, mine)

    assert written["oauth"] == mine
    # The user's own file is read, never edited.
    assert stored["oauth"] == mine


@pytest.mark.parametrize("mine", [MINE_NO_SECRET, MINE_WITH_SECRET], ids=["no-secret", "secret"])
def test_a_rebuild_on_kas_keeps_the_client_of_the_owners_recorded_server(
    tmp_path, monkeypatch, mine
):
    """Preview on, chats on KAS, no Slack app saved: the owner's client stays in the spec.

    The entry is in the sealed owner record. The owner's server signs in with the
    ``clientId`` in this entry (``crew_oauth_dcr.prepare_custom``); without one it
    would ask Slack for dynamic registration, which Slack does not offer. The
    operator's projected client and secret from the previous spec are gone.
    """
    monkeypatch.setattr(crew_oauth, "strips_spec_secret", lambda slug: True)

    written, stored = _rebuilt_slack_entry(tmp_path, monkeypatch, mine, recorded=True)

    assert written["oauth"] == mine
    assert written["oauth"]["clientId"] == "mine"
    assert "op-secret" not in json.dumps(written)
    assert stored["oauth"] == mine


@pytest.mark.parametrize("mine", [MINE_NO_SECRET, MINE_WITH_SECRET], ids=["no-secret", "secret"])
def test_a_rebuild_on_kas_strips_the_client_of_an_entry_the_owner_did_not_record(
    tmp_path, monkeypatch, mine
):
    """The same entry with no sealed owner record, as an agent's append would leave it.

    Nothing reads the oauth block of such an entry on KAS with the preview on, so
    the spec holds no client for it, and no ``clientSecret``. The user's file is
    not edited.
    """
    monkeypatch.setattr(crew_oauth, "strips_spec_secret", lambda slug: True)

    written, stored = _rebuilt_slack_entry(tmp_path, monkeypatch, mine)

    assert "oauth" not in written
    assert "my-own-secret" not in json.dumps(written)
    assert stored["oauth"] == mine


def test_the_kas_strip_strips_everything_when_the_owner_record_cannot_be_read(monkeypatch):
    """An unreadable sealed record proves nothing: the client does not come back."""
    import kiro_crew.config.loader as loader
    from kiro_crew import agent as agent_mod

    def unreadable():
        raise OSError("config.json unreadable")

    monkeypatch.setattr(crew_oauth, "strips_spec_secret", lambda slug: True)
    monkeypatch.setattr(loader, "read_config_for_update", unreadable)
    entry = {"url": SLACK_URL, "oauth": dict(MINE_WITH_SECRET)}
    source = {SLUG: {"url": SLACK_URL, "oauth": dict(MINE_WITH_SECRET)}}

    out = agent_mod._apply_operator_oauth_client(SLUG, entry, managed=True, raw_scopes=(source,))

    assert "oauth" not in out


def test_a_rebuild_on_kas_leaves_no_client_when_the_user_wrote_none(tmp_path, monkeypatch):
    """The same rebuild for an entry with no client of the user's: nothing is put back."""
    monkeypatch.setattr(crew_oauth, "strips_spec_secret", lambda slug: True)

    written, _stored = _rebuilt_slack_entry(tmp_path, monkeypatch, {})

    assert "oauth" not in written
    assert "op-secret" not in json.dumps(written)


@pytest.mark.parametrize(
    "mine", [{}, MINE_NO_SECRET, MINE_WITH_SECRET], ids=["none", "no-secret", "secret"]
)
def test_the_kas_strip_removes_the_operators_client_and_keeps_only_the_users(monkeypatch, mine):
    """An entry that carries the operator's projection: all three owned keys go.

    Only what the user wrote in the source scope comes back, so the operator's
    client id and secret cannot stay in the spec through this branch.
    """
    from kiro_crew import agent as agent_mod

    import kiro_crew.config.loader as loader

    record = {"connections": {"owner_mcp_servers": {SLUG: {"url": SLACK_URL}}}}
    monkeypatch.setattr(loader, "read_config_for_update", lambda: record)
    monkeypatch.setattr(crew_oauth, "strips_spec_secret", lambda slug: True)
    projected = {"clientId": "op", "clientSecret": "op-secret", "redirectUri": REDIRECT}
    entry = {"url": SLACK_URL, "oauth": {**projected, "issuer": "https://slack.com"}}
    source = {SLUG: {"url": SLACK_URL, **({"oauth": dict(mine)} if mine else {})}}

    out = agent_mod._apply_operator_oauth_client(SLUG, entry, managed=True, raw_scopes=(source,))

    assert out["oauth"] == {"issuer": "https://slack.com", **mine}
    assert "op-secret" not in json.dumps(out)


def test_a_provider_projected_before_the_copy_strip_still_loses_a_stale_client():
    """GitHub's source entries may hold an old projected copy: no user client is read."""
    from kiro_crew.connections.oauth_clients import user_oauth_client

    github = registry.get_provider("github")["mcp_url"]
    scopes = ({"github": {"url": github, "oauth": {"clientId": "c", "clientSecret": "s"}}},)
    assert user_oauth_client("github", github, scopes) == {}
    slack = ({SLUG: {"url": SLACK_URL, "clientId": "mine"}},)
    assert user_oauth_client(SLUG, SLACK_URL, slack) == {"clientId": "mine"}
    # Another endpoint under the same name is somebody else's server.
    assert user_oauth_client(SLUG, SLACK_URL, ({SLUG: {"url": "https://x/mcp"}},)) is None


def test_a_client_cleared_in_a_higher_scope_does_not_come_back_from_a_lower_one():
    """The first scope with a matching entry decides, even when it holds no client."""
    from kiro_crew.connections.oauth_clients import user_oauth_client

    cleared = {SLUG: {"url": SLACK_URL}}
    lower = {SLUG: {"url": SLACK_URL, "oauth": {"clientId": "old"}}}
    assert user_oauth_client(SLUG, SLACK_URL, (cleared, lower)) == {}
    # A higher scope with no slack entry at all still falls through.
    assert user_oauth_client(SLUG, SLACK_URL, ({}, lower)) == {"clientId": "old"}


def test_a_top_level_client_id_clear_wins_over_a_stale_nested_one():
    """An explicit top-level ``clientId: ""`` clears; the old ``oauth.clientId`` stays gone."""
    from kiro_crew.connections.oauth_clients import user_oauth_client

    entry = {"url": SLACK_URL, "clientId": "", "oauth": {"clientId": "old", "redirectUri": "r"}}
    assert user_oauth_client(SLUG, SLACK_URL, ({SLUG: entry},)) == {"redirectUri": "r"}


@pytest.mark.parametrize("mine", [MINE_NO_SECRET, MINE_WITH_SECRET], ids=["no-secret", "secret"])
def test_a_scope_copy_carries_the_users_client_never_the_rendered_one(tmp_path, monkeypatch, mine):
    """Copying the rendered ``slack`` entry into a scope takes the user's own client
    from the source file, never the operator's from the render."""
    from kiro_crew.dashboard.handlers import mcp as mcp_handlers

    store = tmp_path / "mcp.json"
    store.write_text(
        json.dumps({"mcpServers": {SLUG: {"url": SLACK_URL, "oauth": dict(mine)}}}),
        encoding="utf-8",
    )
    agents = tmp_path / "agents"
    agents.mkdir()
    rendered = {
        "url": SLACK_URL,
        "oauth": {"clientId": "op", "clientSecret": "op-secret", "redirectUri": "r"},
    }
    (agents / "kirocrew.json").write_text(
        json.dumps({"mcpServers": {SLUG: rendered}}), encoding="utf-8"
    )
    monkeypatch.setattr(mcp_handlers, "kiro_agents_dir", lambda: agents)
    monkeypatch.setattr(mcp_handlers, "_read_agent_spec", lambda p, **_k: json.loads(p.read_text()))
    monkeypatch.setattr(mcp_handlers, "_kirocrew_mcp_json", lambda: store)
    monkeypatch.setattr(mcp_handlers, "_GLOBAL_MCP_JSON", tmp_path / "absent.json")
    monkeypatch.setattr(mcp_handlers, "_extra_mcp_scopes", lambda: [])

    found = mcp_handlers._find_server_spec_anywhere(SLUG)
    assert found["oauth"] == mine


def test_a_scope_copy_keeps_the_client_of_an_entry_only_the_agent_spec_has(tmp_path, monkeypatch):
    """No source scope has the entry, so the rebuild keeps it verbatim: its client
    is the user's own, and copying it into a scope must not drop it."""
    from kiro_crew.dashboard.handlers import mcp as mcp_handlers

    agents = tmp_path / "agents"
    agents.mkdir()
    rendered = {"url": SLACK_URL, "oauth": dict(MINE_WITH_SECRET)}
    (agents / "kirocrew.json").write_text(
        json.dumps({"mcpServers": {SLUG: rendered}}), encoding="utf-8"
    )
    monkeypatch.setattr(mcp_handlers, "kiro_agents_dir", lambda: agents)
    monkeypatch.setattr(mcp_handlers, "_read_agent_spec", lambda p, **_k: json.loads(p.read_text()))
    monkeypatch.setattr(mcp_handlers, "_kirocrew_mcp_json", lambda: tmp_path / "absent-store.json")
    monkeypatch.setattr(mcp_handlers, "_GLOBAL_MCP_JSON", tmp_path / "absent.json")
    monkeypatch.setattr(mcp_handlers, "_extra_mcp_scopes", lambda: [])

    found = mcp_handlers._find_server_spec_anywhere(SLUG)
    assert found["oauth"] == MINE_WITH_SECRET


# --- the MCP table: the card claims a slack row only once it can sign in ------------


def _table_rows() -> list[dict]:
    github = registry.get_provider("github")["mcp_url"]
    return [
        {"name": SLUG, "url": SLACK_URL},
        {"name": "github", "url": github},
        {"name": SLUG, "url": "https://slack.example.com/mcp"},
        {"name": "docs", "url": "https://docs.example.com/mcp"},
        *({"name": SLUG, "url": variant} for variant in _url_variants(SLACK_URL)),
    ]


def test_a_slack_row_is_left_to_its_own_sign_in_while_no_oauth_app_is_saved(tmp_path, monkeypatch):
    """No OAuth Apps record: the card could only fail, so the row is not the card's.

    GitHub's row, as unconfigured as Slack's here, keeps its card. A slack row at a
    trailing-slash or letter-case variant is one the card owns too, so it is marked.
    """
    from kiro_crew.dashboard.handlers import mcp_probe

    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
    monkeypatch.delenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_SECRET", raising=False)
    rows = _table_rows()

    mcp_probe._annotate_unconfigured_connection(rows)

    assert [row.get("connectionUnconfigured") for row in rows] == [
        True,
        None,
        None,
        None,
        True,
        True,
    ]


def test_the_card_claims_the_slack_row_once_its_oauth_app_is_saved(tmp_path, monkeypatch):
    """Client ID and Secret saved: no flag, and a stale one from a cached row goes."""
    from kiro_crew.dashboard.handlers import mcp_probe

    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
    (tmp_path / "config.json").write_text(
        json.dumps({"connections": {"oauth_clients": {SLUG: {"client_id": "123.456"}}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("KIROCREW_CONNECTIONS_SLACK_CLIENT_SECRET", "sec")
    rows = _table_rows()
    rows[0]["connectionUnconfigured"] = True

    mcp_probe._annotate_unconfigured_connection(rows)

    assert all("connectionUnconfigured" not in row for row in rows)
