from dataclasses import dataclass
from typing import Generic, TypeVar, Optional

T = TypeVar('T')


@dataclass
class NoctuaResult(Generic[T]):
    ok: bool
    value: Optional[T] = None
    error_code: int = 0
    error_message: str = ""

    @classmethod
    def success(cls, value: T = None) -> 'NoctuaResult[T]':
        return cls(ok=True, value=value)

    @classmethod
    def error(cls, code: int, message: str = "") -> 'NoctuaResult[T]':
        return cls(ok=False, error_code=code, error_message=message)

    def is_ok(self) -> bool:
        return self.ok

    def is_err(self) -> bool:
        return not self.ok

    def unwrap(self) -> Optional[T]:
        return self.value

    def __repr__(self) -> str:
        if self.ok:
            return f"OK({self.value})"
        return f"ERR({self.error_code}: {self.error_message})"
