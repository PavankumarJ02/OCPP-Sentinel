# =============================================================================
# models/__init__.py — Makes the models directory a Python package
# =============================================================================
#
# LEARNING NOTE:
# This __init__.py re-exports the key classes from ocpp_messages.py so
# that other parts of the code can do:
#     from ocpp_sentinel.models import OCPPMessage, AuthorizePayload
# instead of the longer:
#     from ocpp_sentinel.models.ocpp_messages import OCPPMessage, AuthorizePayload
#
# This is called "public API design" — you control what's easy to import.
# =============================================================================

from ocpp_sentinel.models.ocpp_messages import (
    # The main message envelope
    OCPPMessage,
    AnalysisContext,
    # Individual payload types
    AuthorizePayload,
    BootNotificationPayload,
    StartTransactionPayload,
    StopTransactionPayload,
    MeterValuesPayload,
    StatusNotificationPayload,
    RemoteStartTransactionPayload,
    # Sub-models used inside payloads
    SampledValue,
    MeterValue,
)

# __all__ controls what gets exported when someone does:
#     from ocpp_sentinel.models import *
# It's good practice to define this explicitly.
__all__ = [
    "OCPPMessage",
    "AnalysisContext",
    "AuthorizePayload",
    "BootNotificationPayload",
    "StartTransactionPayload",
    "StopTransactionPayload",
    "MeterValuesPayload",
    "StatusNotificationPayload",
    "RemoteStartTransactionPayload",
    "SampledValue",
    "MeterValue",
]
