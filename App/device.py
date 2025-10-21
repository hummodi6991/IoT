
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class Device:
    id: str
    name: str
    online: bool
    battery: Optional[int] = None
    extra: Optional[Dict[str, Any]] = None
