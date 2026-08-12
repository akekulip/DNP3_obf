"""Timing-policy characterization toolkit for the DNP3 Defense-4 timing engine.

Software/analysis only. Loads a baseline registry of committed timing datasets,
validates their schema/units/timing-definitions, rejects incompatible pooling,
and evaluates candidate (D_A, D_R) deadline policies against the evidenced native
CLRT distribution. Nothing here touches hardware, the switch, or the relay.
"""

__all__ = ["repo", "registry", "stats", "policy"]
