"""DSCP allocation: one class-selector code point per WAN number.

WANn → CSn. CSn is DSCP 8n, which is TOS byte 32n once shifted past the two
ECN bits — the value setsockopt(IP_TOS) wants and the value tcpdump prints.
Seven slots (CS1..CS7); CS0 is the default class and would match unmarked
traffic, so WAN numbers outside 1..7 are refused rather than wrapped.
"""

MAX_WAN = 7


class DscpError(ValueError):
    pass


def allocate(wan_number):
    """Return (opnsense_tos_name, tos_byte) for a WAN number."""
    if not isinstance(wan_number, int) or not 1 <= wan_number <= MAX_WAN:
        raise DscpError(f"WAN number {wan_number!r} has no DSCP slot (1..{MAX_WAN})")
    return f"cs{wan_number}", 32 * wan_number


def tos_hex(tos_byte):
    return f"0x{tos_byte:02x}"
