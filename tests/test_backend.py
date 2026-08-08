from __future__ import annotations

from fourwayhs.backend import AircrackBackend, get_backend
from fourwayhs.native_backend import NativeLinuxBackend


def test_get_backend_aircrack():
    backend = get_backend("aircrack")
    assert isinstance(backend, AircrackBackend)
    assert backend.name == "aircrack"


def test_get_backend_native():
    backend = get_backend("native")
    assert isinstance(backend, NativeLinuxBackend)
    assert backend.name == "native"


def test_get_backend_unknown_raises():
    try:
        get_backend("bogus")
        assert False, "expected ValueError"
    except ValueError:
        pass


if __name__ == "__main__":
    test_get_backend_aircrack()
    test_get_backend_native()
    test_get_backend_unknown_raises()
    print("OK: backend tests passed")
