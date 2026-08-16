"""Credentialed inspection: reading ground truth from devices we can log into.

One adapter so far — generic SSH — selected by `CapabilityInspectorRegistry` from what a
device can do rather than what it is called. Vendor adapters (VAPIX, ISAPI, embedded
BusyBox SSH) register here later without any caller changing (m1-design §1).

Everything in this package is read-only against the device, and the credential reaches the
transport and nowhere else (AGENTS.md §2.4, §2.10).
"""
