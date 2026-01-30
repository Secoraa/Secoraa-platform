from typing import List, Optional

from pydantic import BaseModel


class GenericScanPayload(BaseModel):
    domain: Optional[str] = None
    subdomains: Optional[List[str]] = None
    target_ip: Optional[str] = None
    asset_group_id: Optional[str] = None


class CreateScanRequest(BaseModel):
    scan_name: str
    scan_type: str
    payload: GenericScanPayload

