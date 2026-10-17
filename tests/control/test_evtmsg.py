from xvm_control import evtmsg

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SEC = "Microsoft-Windows-Security-Auditing"


def _event(provider, event_id, data, message, version=0, user_data=False):
    body = (
        "<UserData><X/></UserData>"
        if user_data
        else "<EventData>"
        + "".join(f"<Data Name='{n}'>{v}</Data>" for n, v in data)
        + "</EventData>"
    )
    return (
        f"<Event xmlns='{NS}'><System><Provider Name='{provider}'/><EventID>{event_id}</EventID>"
        f"<Version>{version}</Version></System>{body}"
        f"<RenderingInfo Culture='en-US'><Message>{message}</Message></RenderingInfo></Event>"
    )


def _events(*evs):
    return "﻿<Events>" + "".join(evs) + "</Events>"


def _logon(user, domain, logon_type, version=2):
    msg = (
        "An account was successfully logged on.\r\n\r\nNew Logon:\r\n"
        f"\tAccount Name:\t\t{user}\r\n\tAccount Domain:\t\t{domain}\r\n"
        f"\tLogon Type:\t\t{logon_type}\r\n\r\nThis event is generated when a logon session "
        "is created. 100% sure."
    )
    return _event(
        SEC,
        4624,
        [("TargetUserName", user), ("TargetDomainName", domain), ("LogonType", logon_type)],
        msg,
        version,
    )


def test_parse_rendered():
    samples, notes = evtmsg.parse_rendered(
        _events(
            _logon("bob", "EDGE", "3"),
            _event("Svc", 1, [], "", 0),  # no message: skipped
            _event("U", 2, [], "user data", 0, user_data=True),
        )
    )
    assert len(samples) == 1
    s = samples[0]
    assert (s.provider, s.event_id, s.version) == (SEC, 4624, 2)
    assert s.values == ["bob", "EDGE", "3"]
    assert "\r" not in s.message  # XML parsing normalises line ends
    assert notes == ["U 2: UserData events skipped"]
    assert evtmsg.parse_rendered("<Events><Event")[1][0].startswith("rendered events unreadable")


def test_derive_from_several_events():
    samples, _ = evtmsg.parse_rendered(
        _events(
            _logon("bob", "EDGE", "3"),
            _logon("alice", "EDGE", "2"),
            _logon("svc-x", "CORP", "5"),
        )
    )
    templates, notes = evtmsg.derive(samples)
    t = templates[SEC]["4624/2"]
    assert t == (
        "An account was successfully logged on.\r\n\r\nNew Logon:\r\n"
        "\tAccount Name:\t\t%1\r\n\tAccount Domain:\t\t%2\r\n\tLogon Type:\t\t%3\r\n\r\n"
        "This event is generated when a logon session is created. 100%% sure."
    )
    assert templates[SEC]["4624"] == t  # one version seen
    assert notes == []


def test_short_values_only_as_whole_fields():
    # "3" also appears inside "Windows 3x"; only the field at the line end is the value.
    msg = "Windows 3x said:\n\tLogon Type:\t3\n\tAccount:\tbob"
    msg2 = "Windows 3x said:\n\tLogon Type:\t2\n\tAccount:\tann"
    samples, _ = evtmsg.parse_rendered(
        _events(
            _event("P", 7, [("LogonType", "3"), ("User", "bob")], msg),
            _event("P", 7, [("LogonType", "2"), ("User", "ann")], msg2),
        )
    )
    templates, _ = evtmsg.derive(samples)
    assert templates["P"]["7/0"] == "Windows 3x said:\r\n\tLogon Type:\t%1\r\n\tAccount:\t%2"


def test_repeated_value_and_parameter_strings():
    # Windows resolves %%1833 before rendering, so that field stays literal and
    # another event with a different parameter cannot be reproduced.
    a = _event(
        "P", 9, [("User", "bob"), ("Level", "%%1833")], "User bob asked for Impersonation as bob."
    )
    b = _event(
        "P", 9, [("User", "ann"), ("Level", "%%1833")], "User ann asked for Impersonation as ann."
    )
    c = _event(
        "P", 9, [("User", "eve"), ("Level", "%%1834")], "User eve asked for Delegation as eve."
    )
    samples, _ = evtmsg.parse_rendered(_events(a, b, c))
    templates, notes = evtmsg.derive(samples)
    assert templates["P"]["9/0"] == "User %1 asked for Impersonation as %1."
    assert notes == ["P 9 v0: template reproduces 2 of 3 distinct events"]


def test_unconfirmed_templates_are_dropped():
    # Two events whose texts share no structure: no candidate reproduces both.
    a = _event("P", 5, [("X", "one")], "First wording one.")
    b = _event("P", 5, [("X", "two")], "Second phrasing two!")
    templates, notes = evtmsg.derive(evtmsg.parse_rendered(_events(a, b))[0])
    assert templates == {}
    assert notes == ["P 5 v0: template reproduced only its own event of 2; dropped"]


def test_single_events_and_versions():
    a = _event("P", 1, [("X", "solo")], "Only solo here.", version=0)
    b = _event("P", 1, [("X", "solo")], "Version one says solo.", version=1)
    templates, _ = evtmsg.derive(evtmsg.parse_rendered(_events(a, b))[0])
    assert templates["P"] == {"1/0": "Only %1 here.", "1/1": "Version one says %1."}
    # Two versions: no bare "1" key, since the engine could not tell which one an
    # event without a version means.
