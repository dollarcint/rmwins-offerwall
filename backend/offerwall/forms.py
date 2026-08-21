from django import forms

from .models import Publisher
from .security import generate_signing_secret


class PublisherAdminForm(forms.ModelForm):
    rotate_signing_secret = forms.BooleanField(
        required=False,
        help_text="Generate a new signing secret. The plaintext value is shown once after saving.",
    )
    rotate_api_key = forms.BooleanField(
        required=False,
        help_text="Generate a new inventory API key. The plaintext value is shown once after saving.",
    )

    class Meta:
        model = Publisher
        fields = "__all__"

    def save(self, commit=True):
        instance = super().save(commit=False)
        if self.cleaned_data.get("rotate_signing_secret"):
            instance.set_signing_secret(generate_signing_secret())
        if self.cleaned_data.get("rotate_api_key"):
            instance.rotate_api_key()
        if commit:
            instance.save()
            self.save_m2m()
        return instance
