# pyright: reportMissingImports=false

import logging
import sys

from desfire import DESFire, PN532UARTDevice

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create physical device which can be used to detect a card.
# A legacy serial path is translated to the nfcpy path tty:AMA2:pn532.
device = PN532UARTDevice("/dev/ttyAMA2")

# Wait for a card
uid = None
i = 0

while not uid and i < 10:
    logger.info("Connecting to card (attempt %s)...", i + 1)
    uid = device.wait_for_card(timeout=1)
    i += 1

if not uid:
    logger.error("No card detected!")
    sys.exit(1)

logger.info("Card detected.")

# Create DESFire object, which allows further communication with the card
desfire = DESFire(device)
print(desfire.get_card_version())
