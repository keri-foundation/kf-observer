# -*- encoding: utf-8 -*-
"""Small helpers for cooperative outbound HTTP work."""

from hio.core import http


def responseDo(owner, client, timeout=5.0, clientDoer=None):
    """Wait for one HTTP response while yielding to the hio scheduler.

    Parameters:
        owner (DoDoer): parent scheduler that owns the request.
        client (http.clienting.Client): already configured and requested client.
        timeout (float): maximum simulated seconds to wait.
        clientDoer (Doer | None): optional doer override for deterministic tests.

    Returns:
        HTTPResponse | None: parsed response, or ``None`` on timeout/error.
    """
    clientDoer = clientDoer or http.clienting.ClientDoer(client=client)
    owner.extend([clientDoer])
    deadline = owner.tyme + float(timeout)
    try:
        while not client.responses and owner.tyme < deadline:
            respondent = client.respondent
            if respondent is not None and respondent.errored:
                break
            yield 0.1
        if not client.responses:
            return None
        return client.respond()
    finally:
        owner.remove([clientDoer])
