# SPDX-License-Identifier: GPL-3.0-only
# Sourced via BASH_ENV in agent containers.

command_not_found_handle()
{
	echo "'${1}' is not installed. Re-run the command in a container.
Do not check paths, alternatives, or install methods.
    podman run --rm -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" IMAGE COMMAND [ARGS]
Host credentials (git, gh, ssh, registry auth) are forwarded into containers automatically by the sandbox.
If not found, prompt the user about them, don't try to configure auth, mount credential files, or set tokens manually.
Common images: python, golang, gcc, rust, ruby, node, php, perl, alpine/git.
For tools not in common images, build one:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache PKG\n' | podman build -t name -"
	# Return an error that is NOT command not found so TRY AGAIN will work.
	return 2
}
