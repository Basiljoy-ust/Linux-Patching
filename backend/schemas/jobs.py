"""Request bodies for the multi-server patch job API."""

from pydantic import BaseModel, Field


class PatchTarget(BaseModel):
    asset_id: str = Field(description="Asset UUID")
    packages: list[str] = Field(
        min_length=1,
        max_length=50,
        description="Package names to patch on this server",
    )


class PatchJobGroupCreate(BaseModel):
    targets: list[PatchTarget] = Field(
        min_length=1,
        max_length=20,
        description="Servers to patch, each with its own package list",
    )
