"""AC-2227 — central bot router + send throttle in gaius_common.utils.telegram.

Each destination Topic maps to exactly one of the 6 bots (the sender identity);
the legacy per-service ``bot`` arg is only a fallback. Sends are rate-limited per
chat and honour Telegram's 429 retry_after before degrading to Google Chat."""
import os

# Token env must be set before importing the module reads them at call time;
# rate disabled so the throttle never sleeps in the routing tests.
os.environ.update({
    "GAIUS_TGBOT_TOKEN": "cmd:tok",
    "GAIUS_REPORT_BOT_TOKEN": "rep:tok",
    "GAIUS_INTERNAL_SERVICE_BOT_TOKEN": "svc:tok",
    "GAIUS_ALERT_BOT_TOKEN": "alr:tok",
    "GAIUS_JENKINS_BOT_TOKEN": "ci:tok",
    "GAIUS_CROWDSEC_BOT_TOKEN": "cs:tok",
    "NOTIFICATION_MSGS_PER_SEC": "0",
})

from unittest import mock

from gaius_common.utils import telegram as tg


class FakeBot:
    def __init__(self, token):
        self._token = token


def test_topic_to_bot_mapping():
    T = tg.Topic
    assert tg.bot_token_for(T.PAYMENTS) == "rep:tok"
    assert tg.bot_token_for(T.CERTIFICATES) == "rep:tok"
    assert tg.bot_token_for(T.USER) == "rep:tok"
    assert tg.bot_token_for(T.CRITICAL_ERRORS) == "svc:tok"
    assert tg.bot_token_for(T.APP_ERRORS) == "svc:tok"
    assert tg.bot_token_for(T.SA_OPERATIONS) == "svc:tok"
    assert tg.bot_token_for(T.CDN) == "svc:tok"
    assert tg.bot_token_for(T.EMERGENCY) == "alr:tok"
    assert tg.bot_token_for(T.ATTACK_MONITOR) == "alr:tok"
    assert tg.bot_token_for(T.PROTECTION_MONITOR) == "alr:tok"
    assert tg.bot_token_for(T.UPSTREAM_MONITOR) == "alr:tok"
    assert tg.bot_token_for(T.CROWDSEC_BANS) == "cs:tok"   # kept on @GaiusCrowdsecBot
    assert tg.bot_token_for(T.TOOLS) == "cmd:tok"
    assert tg.bot_token_for(bot_class="ci") == "ci:tok"    # explicit class (Jenkins)
    assert tg.bot_token_for("-100999_111") == ""           # unmapped topic -> no central bot


def test_central_bot_overrides_passed_legacy_bot():
    sent = {}
    with mock.patch.object(tg.telegram, "Bot", FakeBot, create=True), \
         mock.patch.object(tg, "_send_once", lambda bot, *a, **k: sent.update(token=bot._token)):
        tg._bot_cache.clear()
        ok = tg.send_telegram_notification(FakeBot("legacy:tok"), tg.Topic.PAYMENTS, "hi")
    assert ok is True
    assert sent["token"] == "rep:tok"   # routed to @GaiusReportBot, NOT the legacy bot


def test_429_retry_after_then_success():
    calls = []

    class FakeRetryAfter(Exception):
        retry_after = 0

    def flaky(bot, *a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise FakeRetryAfter()

    with mock.patch.object(tg.telegram, "Bot", FakeBot, create=True), \
         mock.patch.object(tg.time, "sleep", lambda s: None), \
         mock.patch.object(tg, "_send_once", flaky):
        tg._bot_cache.clear()
        ok = tg.send_telegram_notification(None, tg.Topic.EMERGENCY, "x")
    assert ok is True and len(calls) == 2   # honoured retry_after, retried, succeeded


def test_no_central_token_and_no_bot_falls_back_to_gchat():
    with mock.patch.object(tg, "_gchat_fallback", lambda m: True) as gc:
        ok = tg.send_telegram_notification(None, "-100999_111", "x")  # unmapped, no bot
    assert ok is False


def test_throttle_smooths_burst():
    sleeps = []
    with mock.patch.object(tg, "_THROTTLE_RATE", 1.0), \
         mock.patch.object(tg, "_THROTTLE_BURST", 3), \
         mock.patch.object(tg.time, "sleep", lambda s: sleeps.append(s)), \
         mock.patch.object(tg.time, "monotonic", lambda: 1000.0):  # frozen clock
        tg._buckets.clear()
        for _ in range(3):
            tg._throttle(tg.Topic.PAYMENTS)
        assert sleeps == []              # burst of 3 passes freely
        tg._throttle(tg.Topic.PAYMENTS)  # 4th exhausts the bucket
        assert sleeps and sleeps[0] > 0  # must wait ~1s for a refill


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception:
            failed += 1
            print("FAIL", fn.__name__)
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
