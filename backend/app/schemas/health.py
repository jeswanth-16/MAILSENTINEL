from pydantic import BaseModel, Field

class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Status of the API service")
    service: str = Field(default="mailsentinel-api", description="Service identifier")
    version: str = Field(default="0.1.0", description="API version")
