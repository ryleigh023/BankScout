from pydantic import BaseModel

class SecurityLog(BaseModel):
    timestamp: str
    user: str
    ip: str
    event_type: str
    device: str
