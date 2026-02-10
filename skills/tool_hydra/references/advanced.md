# Advanced Techniques

## Module Options
- Use `hydra -U <module>` to list module-specific options.
- `-C` supports `login:pass` combo files; `-e nsr` adds null/reversed checks.

## Rate & Session Control
- Use `-t` to limit parallel tasks and `-W/-w` for timeouts.
- `-R` restores a previous session; `-f/-F` stop after first valid hit.
