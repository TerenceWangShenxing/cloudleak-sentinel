from abc import ABC, abstractmethod
from typing import Iterable
from ..models import Artifact


class SourceAdapter(ABC):
    channel = 'unknown'

    @abstractmethod
    def collect(self) -> Iterable[Artifact]:
        raise NotImplementedError
