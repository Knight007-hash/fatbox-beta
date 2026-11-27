"""Host-side controller: drives FatBox inside the VM through VirtualBox guest control.

Runs on the host. Standard library only. Only JSON (sample lists, static reports) crosses
from the VM to the host; samples never do. Nothing received from the VM is trusted.
"""
