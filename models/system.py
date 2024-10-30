from models.forms.system import SystemSettingsForm
from pydantic import BaseModel, computed_field
from utils.datetimes import utc_now_as_str


class SystemSettingsBase(BaseModel):
    settings: SystemSettingsForm = SystemSettingsForm()


class UpdateSystemSettings(SystemSettingsBase):
    @computed_field
    @property
    def updated(self) -> str:
        return utc_now_as_str()


model_classes = {
    "forms": {
        "settings": SystemSettingsForm,
    },
}
