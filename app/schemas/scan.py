from typing import List, Optional

from pydantic import BaseModel


class GenericScanPayload(BaseModel):
    domain: str
    subdomains: Optional[List[str]] = None


class CreateScanRequest(BaseModel):
    scan_name: str
    scan_type: str
    payload: GenericScanPayload

