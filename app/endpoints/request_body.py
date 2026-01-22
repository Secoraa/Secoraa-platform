from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class DomainRequestBody(BaseModel):
    domain_name: str = Field(
        ...,
        example="example.com",
        min_length=3,
    )
    tags: Optional[List[str]] = Field(
        default=None,
        example=["production", "external"],
    )

class DomainUpdateRequestBody(BaseModel):
    tags: List[str]
    
class SubdomainRequestBody(BaseModel):
    domain_id: UUID
    subdomain_name: str = Field(
        ...,
        example="api.example.com",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        example=["api", "critical"],
    )


class IPAddressRequestBody(BaseModel):
    domain_id: UUID
    ipaddress_name: str = Field(
        ...,
        example="93.184.216.34",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        example=["external"],
    )


class URLRequestBody(BaseModel):
    domain_id: UUID
    url_name: str = Field(
        ...,
        example="https://example.com/login",
    )
    tags: Optional[List[str]] = Field(
        default=None,
        example=["login", "production"],
    )



class SubdomainScanRequest(BaseModel):
    domain: str
    subdomains: Optional[List[str]] = None
    export_json: bool = False
    export_pdf: bool = False

