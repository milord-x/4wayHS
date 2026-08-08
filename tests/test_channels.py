from __future__ import annotations

from fourwayhs.wifi.channels import channel_to_frequency


def test_channel_1_2_4ghz():
    assert channel_to_frequency(1) == 2412


def test_channel_6_2_4ghz():
    assert channel_to_frequency(6) == 2437


def test_channel_14_special_case():
    assert channel_to_frequency(14) == 2484


def test_channel_36_5ghz():
    assert channel_to_frequency(36) == 5180


def test_channel_149_5ghz():
    assert channel_to_frequency(149) == 5745


def test_unknown_channel_returns_zero():
    assert channel_to_frequency(0) == 0
    assert channel_to_frequency(-1) == 0


if __name__ == "__main__":
    test_channel_1_2_4ghz()
    test_channel_6_2_4ghz()
    test_channel_14_special_case()
    test_channel_36_5ghz()
    test_channel_149_5ghz()
    test_unknown_channel_returns_zero()
    print("OK: channel mapper tests passed")
