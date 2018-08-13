from django.dispatch import Signal


pre_registration = Signal(providing_args=["extra"])
post_registration = Signal(providing_args=["extra"])


