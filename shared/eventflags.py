from enum import Enum

class EventFlags(Enum):
    """
    Example usage:
    ```
    encflags = 0 + EventFlags.PROTECTED
    flags = EventFlags.get_flags(encflags)
    print(encflags)
    print(flags)
    ```
    """

    DISPOSABLE = 1 << 0
    """Event must NOT be saved in the database"""

    PROTECTED = 1 << 1
    """Event must NOT be deleted from the database"""

    @staticmethod
    def get_flags(encflags):
        return [name for name, flag in EventFlags._member_map_.items() if encflags & flag.value]
    
    def __radd__(self, val):
        return self.value + val