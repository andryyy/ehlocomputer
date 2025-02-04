from models.forms.system import SystemSettings
from pydantic import BaseModel, computed_field
from utils.datetimes import utc_now_as_str


class SystemSettingsBase(BaseModel):
    details: SystemSettings = SystemSettings()


class UpdateSystemSettings(SystemSettingsBase):
    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()
