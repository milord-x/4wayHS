from __future__ import annotations


def channel_to_frequency(channel: int) -> int:
    """2.4/5 GHz channel -> center frequency (MHz). 6 GHz channel numbers
    overlap with 2.4 GHz and can't be disambiguated from the number alone;
    not handled here."""
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if 36 <= channel <= 177:
        return 5000 + channel * 5
    return 0
