# Native sandbox sample verification

This directory is a standalone, credential-free probe. Copy **only its contents** to the root of an empty GitHub test repository. The workflow runs on real GitHub-hosted Ubuntu and macOS virtual machines on push or when dispatched manually. Do not copy the Yss Code repository, `.env` files, configuration, or logs.

The Linux probe verifies a Landlock filesystem write boundary, a child process, a minimal stdio MCP write server, and available Python/Node/Go/Rust/Java toolchains. The workflow reports whether user/mount/network/PID namespaces can actually be created. If namespace creation is unavailable, the result does **not** certify full Linux isolation.

The macOS probe signs a minimal app with the Apple App Sandbox entitlement and checks that the app and its child cannot write outside the sandbox. It does **not** verify a user-selected project folder or a security-scoped bookmark; that needs an interactive Mac.

The probes do not enable MCP writes in Yss Code. Production integration requires isolating the MCP process before initialization, keeping its lifetime tied to the Run, and applying the existing tool registry, approval, audit, and GitLab delivery gates.
