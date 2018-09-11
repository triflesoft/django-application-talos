from django.dispatch import Signal


pre_registration = Signal(providing_args=["principal", "extra"])
post_registration = Signal(providing_args=["principal", "extra"])

personal_information_changed = Signal(providing_args=["full_name"])
