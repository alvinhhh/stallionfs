# Security

Report suspected vulnerabilities privately through [GitHub security advisories](https://github.com/alvinhhh/stallionfs/security/advisories/new). If private reporting is unavailable, open an issue asking for a private contact without including exploit details or private files.

stallionfs runs locally as your user. It uses an owned `0700` store, validates object IDs before filesystem operations, rejects escaping symlinks, and limits permanent cleanup to managed trash and explicitly selected seeds. Copies have independent file identities and Git indexes.

Preparation commands and agents have your user's access. A workspace is a separate working copy, not a security sandbox. Use an operating-system sandbox or a VM when running untrusted code. Do not place credentials in command arguments or commit them to source; an explicitly requested setup command can write secrets into a seed, which will then be copied to its workspaces.

There is no server, telemetry, credential store or network listener. The Git and setup commands you request can use the network. Supported security fixes apply to the latest release.
