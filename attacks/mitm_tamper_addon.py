"""mitmproxy add-on: tamper with and replay QuantumSign traffic for real.

This is the "live" version of run_attacks.py, using mitmproxy as the
man-in-the-middle between the client and the server.

1. pip install mitmproxy
2. Start the API:            python -m quantumsign.server            (port 5000)
3. Start mitmproxy as a reverse proxy in front of it:
       mitmdump -s attacks/mitm_tamper_addon.py --mode reverse:http://127.0.0.1:5000 -p 8080
4. Send requests through the proxy:
       python -m quantumsign.client --url http://127.0.0.1:8080 transfer alice bob 10

Set MODE below:
    "tamper"  changes the amount in every /api/transfer and /insecure/transfer body
    "replay"  lets the request through, then sends an exact copy a second time
"""

import json

from mitmproxy import ctx, http

MODE = "tamper"
NEW_AMOUNT = 900


class QuantumSignAttacker:
    def request(self, flow: http.HTTPFlow) -> None:
        if MODE != "tamper" or not flow.request.path.endswith("/transfer"):
            return
        try:
            body = json.loads(flow.request.get_text())
        except (ValueError, TypeError):
            return
        ctx.log.warn(f"TAMPER: amount {body.get('amount')} -> {NEW_AMOUNT}")
        body["amount"] = NEW_AMOUNT
        flow.request.set_text(json.dumps(body))  # signature headers left untouched

    def response(self, flow: http.HTTPFlow) -> None:
        ctx.log.info(f"{flow.request.method} {flow.request.path} -> {flow.response.status_code} "
                     f"{flow.response.get_text()[:120]}")
        if MODE == "replay" and flow.request.path.endswith("/transfer") and not flow.is_replay:
            ctx.log.warn("REPLAY: resending the captured request")
            ctx.master.commands.call("replay.client", [flow.copy()])


addons = [QuantumSignAttacker()]
