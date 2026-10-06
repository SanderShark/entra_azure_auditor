"""Identity toolkit: search, inspect and (with PIM elevation) edit identities and groups.

Unlike the audit, this WRITES to the tenant. Every change goes through the same pipeline:
build a plan (pure) -> preview it -> confirm -> execute -> record in the local action log.
"""
