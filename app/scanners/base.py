from abc import ABC, abstractmethod

class BaseScanner(ABC):
    name: str

    @abstractmethod
    def run(self, payload: dict) -> dict:
        pass
