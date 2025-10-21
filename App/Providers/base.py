
from abc import ABC, abstractmethod
from typing import List
from app.device import Device

class DeviceStatusProvider(ABC):
    @abstractmethod
    def get_devices(self) -> List[Device]:
        ...
