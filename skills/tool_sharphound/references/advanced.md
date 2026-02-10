# Advanced Techniques

## Focused Collection
- Prefer scoped `--CollectionMethods` rather than `All` to minimize noise and DC load.
- Use looped session collection for time-based visibility: `--CollectionMethods Session --Loop` with `--LoopDuration` and `--LoopInterval` to control run length and cadence.

## DC Targeting
- Pin collection to a specific DC using `--DomainController` when you need deterministic LDAP source selection.

## Output Handling
- SharpHound CE outputs JSON files in a ZIP; plan to ingest multiple ZIPs if you run looped session collection.
