import struct

from ..enums import DESFireCommunicationMode, DESFireFileType
from .file_permissions import FilePermissions


class FileSettings:
    def __init__(
        self,
        encryption: DESFireCommunicationMode | None = None,
        file_type: DESFireFileType | None = None,
        permissions: FilePermissions | None = None,
        file_size: int = 0,
        lower_limit: int = 0,
        upper_limit: int = 0,
        value: int = 0,
        limited_credit_value: int = 0,
        limited_credit_enabled: bool = False,
        record_count: int = 0,
        max_record_count: int = 0
    ):
        """
        Initialize the FileSettings object

        Args:
            encryption (DESFireCommunicationMode | None, optional): Encryption mode that should be applied
                to the file. Can be plain (anyone can read/write), MACed (only authenticated users can read/write)
                or encrypted (only authenticated users can read/write).
            file_type (DESFireFileType | None, optional): Type of the file. Currently only standard files are supported.
            permissions (FilePermissions | None, optional): Permissions that should be applied to the file.
                Refer to the FilePermissions class for more information.
            file_size (int, optional): File size in bytes. Used for standard data files, backup data files and record files (size of one record).
            lower_limit (int, optional): Lower limit for value files.
            upper_limit (int, optional): Upper limit for value files.
            value (int, optional): Value for value files.
            limited_credit_value (int, optional): Limited credit value for value files.
            limited_credit_enabled (bool, optional): Whether limited credit is enabled for value files.
            record_count (int, optional): Current record count for record files.
            max_record_count (int, optional): Maximum record count for record files.
        """
        self.encryption = encryption
        self.file_type = file_type
        self.permissions = permissions

        # file size in data files, record size in record files, not used in value files
        self.file_size = file_size
        # used only for value files
        self.lower_limit = lower_limit
        self.upper_limit = upper_limit
        self.value = value
        self.limited_credit_value = limited_credit_value
        self.limited_credit_enabled = limited_credit_enabled
        # used only for record files
        self.record_count = record_count
        self.max_record_count = max_record_count

    def parse(self, data):
        """
        Takes raw data from command 0xF5 (get file settings) and parses it into a FileSettings object.

        Example of a raw data from command 0xF5 (get file settings on a standard data file):

        ```
        00 03 00 23 08 00 00
        ^^ ^^ ^^^^^ ^^^^^^^^
        |  |  |     |
        |  |  |     ^ File Size (3 bytes)
        |  |  ^ File Permissions (2 bytes)
        |  ^ Communication / Encryption mode (1 byte)
        ^ File Type (1 byte)
        ```

        File permissions are 4 bits each:
            - 0b - 3b: Change Permission key
            - 4b - 7b: Read-Write Permission key
            - 8b - 11b: Write Permission key
            - 12b - 15b: Read Permission key

        There are four other file types that are not implemented yet.
        """

        self.file_type = DESFireFileType(data[0])
        self.encryption = DESFireCommunicationMode(data[1])
        self.permissions = FilePermissions()
        self.permissions.parse(data[2:4])

        if self.file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE or self.file_type == DESFireFileType.MDFT_BACKUP_DATA_FILE:
            # Standard data file, parse file size in bytes. <I is little-endian unsigned int
            self.file_size = struct.unpack("<I", bytes(data[4:7] + [0x00]))[0]
        elif self.file_type == DESFireFileType.MDFT_VALUE_FILE_WITH_BACKUP:
            self.lower_limit = struct.unpack("<I", bytes(data[4:8]))[0]
            self.upper_limit = struct.unpack("<I", bytes(data[8:12]))[0]
            self.limited_credit_value = struct.unpack("<I", bytes(data[12:16]))[0]
            self.limited_credit_enabled = bool(data[16])
        elif self.file_type == DESFireFileType.MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP or self.file_type == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
            self.file_size = struct.unpack("<I", bytes(data[4:7] + [0x00]))[0]
            self.max_record_count = struct.unpack("<I", bytes(data[7:10] + [0x00]))[0]
            self.record_count = struct.unpack("<I", bytes(data[10:13] + [0x00]))[0]
        else:
            # TODO: We currently don't support transaction MAC files
            raise NotImplementedError(f"Filetype {data[0]:02X} is currently not supported.")

    def __repr__(self):
        """
        Returns a human readable representation of the file settings.
        """
        temp = " ----- FileSettings ----\r\n"
        temp += f"File type: {self.file_type.name}\r\n"
        temp += f"Encryption: {self.encryption.name}\r\n"
        temp += f"Permissions: {repr(self.permissions)}\r\n"
        if self.file_type == DESFireFileType.MDFT_STANDARD_DATA_FILE or self.file_type == DESFireFileType.MDFT_BACKUP_DATA_FILE:
            temp += f"File size: {self.file_size}\r\n"
        elif self.file_type == DESFireFileType.MDFT_VALUE_FILE_WITH_BACKUP:
            temp += f"Lower limit: {self.lower_limit}\r\n"
            temp += f"Upper limit: {self.upper_limit}\r\n"
            temp += f"Initial value: {self.value}\r\n"
            temp += f"Limited credit value: {self.limited_credit_value}\r\n"
            temp += f"Limited credit enabled: {self.limited_credit_enabled}\r\n"
        elif self.file_type == DESFireFileType.MDFT_LINEAR_RECORD_FILE_WITH_BACKUP or self.file_type == DESFireFileType.MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
            temp += f"Record size: {self.file_size}\r\n"
            temp += f"Current record count: {self.record_count}\r\n"
            temp += f"Max record count: {self.max_record_count}\r\n"

        return temp
