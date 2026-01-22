from pydantic import BaseModel, Field

class DomainDiscoveryPayload(BaseModel):
    domain: str = Field(
        ...,
        example="example.com",
        description="Root domain to scan"
    )
