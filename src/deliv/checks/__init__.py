"""DNS authentication checks used by ``deliv dns-audit``, one module per protocol.

Each ``check_*`` function takes a :class:`deliv.lib.dns.DNSClient` and a domain, and returns
:class:`deliv.lib.scoring.Finding` objects. Lookup failures become warnings, never exceptions.
"""

#: Remediation shown when a lookup times out or the resolver fails.
RETRY_HINT = "Rerun with a longer --timeout, or point --nameserver at a different DNS server."
