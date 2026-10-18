# Shared native build probes

Read `docs/product-development-loop.md` before changes. This is a labeled capability experiment, not a product build or release. Product source and releases remain on Gitea.

This public probe contains generic fixtures only. Never add private code, source credentials, signing keys, deployment endpoints or infrastructure inventories. Keep fixed standard runner labels and no cache/artifact uploads. Paid runners/resources require separate bounded approval. Workflow inputs must not accept arbitrary shell commands, repositories or revisions. Validate actual native architecture and compiler target; emulation is separate evidence.

Compiler success does not prove GUI, GPU, clipboard, screen capture or installer behavior. Report Metal device absence explicitly. A failed target remains failed; do not silently remove it from the matrix.
