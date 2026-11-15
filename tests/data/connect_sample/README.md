# Sample Entra Connect export (test data)

From Microsoft's AADConnectConfigDocumenter (https://github.com/microsoft/AADConnectConfigDocumenter),
`src/SolutionOutput/Data/Contoso/Production`, MIT licence (see LICENSE.txt). It is the output of
`Get-ADSyncServerConfiguration -Path` for a fictional "contoso.com": the default rule set of that release.

- `SynchronizationRules/`: copied unchanged (62 rules).
- `Connectors/`: REDUCED to each connector's id, name, category and partition filters (the originals carry
  about 1.9 MB of directory schema that the tests don't need).
- `GlobalSettings/`: left out.

Used so the sync-rule tools are tested against the real export format rather than a guess.
