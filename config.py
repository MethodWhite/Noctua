from dataclasses import dataclass, field
from typing import List


@dataclass
class NoctuaConfig:
    min_string_length: int = 4
    max_string_sample: int = 10
    enable_all_modules: bool = True
    verbose: bool = True
    module_filter: List[str] = field(default_factory=list)
