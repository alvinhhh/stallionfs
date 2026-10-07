# Security

Report suspected vulnerabilities privately through [GitHub security advisories](https://github.com/alvinhhh/stallionfs/security/advisories/new). If private reporting is unavailable, open an issue asking for a private contact without including exploit details or private files.

stallionfs runs locally as your user. Workspace storage uses an owned `0700` store and validates object IDs. Preparation rejects escaping symlinks; `gc` and `forget` clean up managed trash and explicitly selected seeds. Workspace copies have independent file identities and Git indexes.

The file commands operate on the paths you select. `clone` copies symlinks without following their targets, including links outside the copied tree. `delete` permanently removes selected paths and refuses mounted directories; it does not inspect whether a regular file is an attached disk image.

Preparation commands and agents have your user's access. A workspace is a separate working copy, not a security sandbox. Use an operating-system sandbox or a VM when running untrusted code. Do not place credentials in command arguments or commit them to source; an explicitly requested setup command can write secrets into a seed, which will then be copied to its workspaces.

There is no server, telemetry, credential store or network listener. The Git and setup commands you request can use the network. Supported security fixes apply to the latest release.
