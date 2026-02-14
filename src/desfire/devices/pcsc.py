# Try importing pyscard
try:
    from smartcard.Exceptions import CardConnectionException
    from smartcard.pcsc.PCSCCardConnection import translateprotocolheader
    from smartcard.scard import SCardGetErrorMessage, SCardTransmit
except ImportError:
    _has_pyscard = False
else:
    _has_pyscard = True

from ..exceptions import DESFireException
from .base import Device


class PCSCDevice(Device):
    """DESFire protocol wrapper for pyscard interface."""

    def __init__(self, card_connection):
        """
        :card_connection: :py:class:`smartcard.pcsc.PCSCCardConnection.PCSCCardConnection` instance.
        Call ``card_connection.connect()`` before calling any DESFire APIs.
        """

        if not _has_pyscard:
            raise ImportError("pyscard is required for using PCSCDevice")

        self.card_connection = card_connection

    def transceive(self, bytes: list[int]) -> list[int]:
        """
        Send in APDU request and wait for the response.

        Args:
            bytes (list[int]): Outgoing bytes as list of bytes or byte array

        Returns:
            list[int]: List of bytes or byte array from the device.
        """
        if not self.card_connection.hcard:
            raise DESFireException(f"Tried to transit to non-open connection: {self.card_connection}")

        protocol = self.card_connection.getProtocol()
        pcscprotocolheader = translateprotocolheader(protocol)

        # http://pyscard.sourceforge.net/epydoc/smartcard.scard.scard-module.html#SCardTransmit
        
        apdu = [0x90, bytes[0], 0x00, 0x00, len(bytes[1:])] + bytes[1:] + ([0x00] if len(bytes[1:]) > 0 else [])

        hresult, response = SCardTransmit(self.card_connection.hcard, pcscprotocolheader, apdu)
        if hresult != 0:
            raise CardConnectionException(
                f"Failed to transmit with protocol {str(pcscprotocolheader)}." + SCardGetErrorMessage(hresult)
            )
        # remove SW 1 and move SW2 to the start of the response
        if len(response) < 2:
            raise CardConnectionException(
                f"Invalid response length {len(response)} from card. Expected at least 2 bytes for SW1 and SW2."
            )
        if response[-2] != 0x91:
            raise CardConnectionException(
                f"Unexpected SW1 {response[-2]:02X} in response from card. Expected 0x91."
            )
        response = [response[-1]] + response[:-2]

        return response
