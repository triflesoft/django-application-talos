from django.dispatch import Signal


pre_registration = Signal(providing_args=["principal", "extra"])
post_registration = Signal(providing_args=["principal", "extra"])


