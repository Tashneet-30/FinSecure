from django.db import models
from django.core.exceptions import ValidationError

class EncryptedField(models.TextField):
    def from_db_value(self, value, expression, connection):
        return value

    def to_python(self, value):
        return value

    def get_prep_value(self, value):
        return value

    def validate(self, value, model_instance):
        # Ensure the value is encrypted
        if not value.startswith('gAAAAA'):
            raise ValidationError('Value must be encrypted')
        return super().validate(value, model_instance)