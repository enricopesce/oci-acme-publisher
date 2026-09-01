# Rollback

Use rollback only after an eligible OCI `PREVIOUS` version is confirmed. The
operation retrieves and validates that version, promotes it with the resource
ETag, confirms `CURRENT`, and can audit endpoint convergence. It never deletes
the failed version first. Retention preserves rollback candidates by operating
only on eligible `DEPRECATED` versions.

