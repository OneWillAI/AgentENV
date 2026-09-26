# Shell Completion

`aenv completion <shell>` prints a shell-completion registration script for the
`aenv` CLI to stdout. Supported shells: `bash`, `zsh`, and `fish`.

The script registers a completion function that calls back into the `aenv`
binary at completion time (`COMPLETE=<shell> aenv ...`), so completion logic
always matches the installed CLI version — upgrading `aenv` does not require
regenerating the script. The script invokes `aenv` by name, so the binary must
be on your `PATH`.

## Generate and install a script

### Bash

```bash
mkdir -p ~/.local/share/bash-completion/completions
aenv completion bash > ~/.local/share/bash-completion/completions/aenv
```

The Bash completion file is loaded on demand by
[`bash-completion`](https://github.com/scop/bash-completion).
This requires `bash-completion` to be installed and initialized in the current
shell.

### Zsh

```zsh
mkdir -p ~/.local/share/zsh/site-functions
aenv completion zsh > ~/.local/share/zsh/site-functions/_aenv
```

Zsh loads completion functions from directories listed in `fpath`.
`~/.local/share/zsh/site-functions` is not included in `fpath` by default on
all systems. Add the following lines to `~/.zshrc` before any existing
`compinit` invocation:

```zsh
fpath=(~/.local/share/zsh/site-functions $fpath)
autoload -Uz compinit
compinit
```

### Fish

```shell
mkdir -p ~/.config/fish/completions
aenv completion fish > ~/.config/fish/completions/aenv.fish
```

## Activate without installing

To test completion for the current shell session without saving a generated
file:

```bash
source <(aenv completion bash)         # Bash
eval "$(aenv completion zsh)"         # Zsh
aenv completion fish | source          # Fish
```

## What completion covers

Static completion covers the full CLI surface:

```bash
aenv <TAB>                       # top-level commands
aenv snapshot <TAB>              # nested subcommands (create, list, ...)
aenv list --output <TAB>         # enum values: table, json
aenv build ./<TAB>               # local path arguments
```

Commands that take a sandbox ID also complete live sandbox IDs dynamically,
filtered to the states each command accepts:

| Command | Completed sandboxes |
|---------|--------------------|
| `pause`, `exec`, `timeout`, `upload`, `download`, `snapshot create` | running |
| `resume` | paused |
| `connect`, `delete` | running and paused |

```bash
aenv resume <TAB>                # paused sandbox IDs
aenv exec <TAB>                  # running sandbox IDs
```

Commands that take a template or a snapshot complete their names first, with
IDs offered as a fallback for resources that have no name. Templates are
filtered to the build statuses each command can act on:

```bash
aenv start <TAB>                 # ready templates and snapshots: names, then IDs
aenv template watch <TAB>        # templates whose build has not finished
aenv template delete <TAB>       # every template, whatever its build did
```

`aenv start --cold` takes an external OCI image reference rather than a local
resource, so it offers no template or snapshot candidates.

Where the shell supports it, candidates carry a description: the template and
state for a sandbox, the underlying ID and build status for a template, and the
underlying ID for a snapshot.

Dynamic lookup is best-effort: it uses short timeouts (500 ms connect, 1 s
request, 2 s in total per completion request) and silently returns no
candidates when credentials, the server, or the network are unavailable. Static
command and flag completion keeps working in that case, and no diagnostic
output is written to your command line. On a deployment large enough to hit
those bounds, typing a longer prefix narrows the lookup and brings back
candidates a shorter prefix had to leave out.
