# Can I approve from an iPhone?

**No iOS app or Face ID approval path ships in v0.6.0.** The unreleased cleanup
retires the experimental mobile scaffold and unwired APNs relay from public core.

Use the [trusted local approver](deployment.md) or an enrolled
[paired desktop workstation](identity.md) for supported human approval. The
paired-device protocol retains the legacy wire name `ios_faceid`; that name
does not establish an iOS or Face ID ceremony.

A mobile approval product remains [deferred](roadmap-deferred.md#ios-second-device-approvals-face-id).
