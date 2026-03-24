import importlib
import math
import os
from typing import Any

from ..exceptions import DESFireException
from .base import Device

nfc: Any | None = None
Type4Tag: Any | None = None

try:
    nfc = importlib.import_module("nfc")
    importlib.import_module("nfc.clf")
    importlib.import_module("nfc.tag")
    Type4Tag = importlib.import_module("nfc.tag.tt4").Type4Tag
except ImportError:
    _has_nfcpy = False
else:
    _has_nfcpy = True


class PN532UARTDevice(Device):
    """
    Wrapper around an nfcpy based connection to a PN532 device.

    The constructor accepts either a legacy serial device path such as
    ``/dev/ttyAMA2`` or an nfcpy device path such as ``tty:AMA2:pn532``.
    """

    def __init__(
        self,
        port: str,
        listen_timeout: float = 1,
        *,
        path: str | None = None,
        sense_interval: float = 0.1,
        transceive_timeout: float | None = None,
        **kwargs,
    ):
        """
        Initializes a device connected to a PN532 device through nfcpy.

        Args:
            port (str): Legacy serial path such as ``/dev/ttyAMA2`` or a fully
                qualified nfcpy device path such as ``tty:AMA2:pn532``.
            listen_timeout (float): Default timeout used by :meth:`wait_for_card`.
            path (str | None): Explicit nfcpy device path. If provided it takes
                precedence over ``port``.
            sense_interval (float): Delay between polling attempts while waiting
                for a card.
            transceive_timeout (float | None): Optional per-command timeout in
                seconds passed to nfcpy.

        Keyword Args:
            Additional keyword arguments are accepted for compatibility with the
            previous pyserial-based implementation and ignored.
        """
        if not _has_nfcpy or nfc is None or Type4Tag is None:
            raise ImportError("nfcpy is required for using PN532UARTDevice")

        self._nfc = nfc
        self._type4_tag_class = Type4Tag
        self._default_wait_timeout = listen_timeout
        self._sense_interval = sense_interval
        self._transceive_timeout = transceive_timeout
        self._ignored_kwargs = dict(kwargs)
        self._target = None
        self._tag = None
        self._path = path or self._resolve_path(port)
        self._clf = self._nfc.ContactlessFrontend()

        if not self._clf.open(self._path):
            raise RuntimeError(f"Failed to open NFC frontend at {self._path}")

    @staticmethod
    def _resolve_path(port: str) -> str:
        if any(port.startswith(prefix) for prefix in ("usb", "tty:", "com:", "udp")):
            return port

        if port.startswith("/dev/tty"):
            return f"tty:{os.path.basename(port)[3:]}:pn532"

        if port.upper().startswith("COM") and port[3:].isdigit():
            return f"com:{port[3:]}:pn532"

        return port

    def close(self) -> None:
        """Close the underlying nfcpy frontend."""
        self._clf.close()
        self._target = None
        self._tag = None

    def __del__(self):
        clf = getattr(self, "_clf", None)
        if clf is None:
            return

        try:
            clf.close()
        except (AttributeError, OSError, RuntimeError):
            pass

    def wait_for_card(self, timeout: float | None = None) -> list[int] | None:
        """Wait for a Type 4 tag and return its UID when found."""
        effective_timeout = self._default_wait_timeout if timeout is None else timeout
        target_request = self._nfc.clf.RemoteTarget("106A")

        if effective_timeout is None:
            while True:
                target = self._clf.sense(target_request, iterations=5, interval=self._sense_interval)
                if target is not None:
                    return self._activate_target(target)

        iterations = max(1, math.ceil(effective_timeout / self._sense_interval))
        target = self._clf.sense(target_request, iterations=iterations, interval=self._sense_interval)
        if target is None:
            return None
        return self._activate_target(target)

    def _activate_target(self, target: Any) -> list[int]:
        tag = self._nfc.tag.activate(self._clf, target)
        if not isinstance(tag, self._type4_tag_class):
            raise DESFireException(f"Detected card is not an ISO-DEP Type 4 tag: {tag!r}")

        self._target = target
        self._tag = tag
        return list(tag.identifier)

    def transceive(self, data: list[int]) -> list[int]:
        """
        Send in APDU request and wait for the response.

        Args:
            data (list[int]): Outgoing bytes as list of bytes or byte array

        Returns:
            list[int]: List of bytes or byte array from the device.
        """
        if self._tag is None or not self._tag.is_present:
            raise DESFireException("No active card present. Call wait_for_card() first.")

        try:
            response = self._tag.transceive(bytearray(data), timeout=self._transceive_timeout)
        except Exception as exc:
            raise DESFireException(f"Failed to transceive with PN532 via nfcpy: {exc}") from exc
        return list(response)
