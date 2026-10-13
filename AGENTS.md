# Opaque public core

This is opaque-dev/opaque. Core libraries, the local broker/CLI/MCP server,
trusted approval verification, independent evidence inspection and local dashboard
belong here. Core must build and operate without private source or enterprise credentials.
Keep public protocols provider-neutral and independently consumable.

Organization SCIM integrations, collaboration delivery adapters, fleet collectors,
enterprise management views and Kubernetes operator implementation belong in the
separate private enterprise repository. Reusability alone does not make code public.
Demo implementation lives in the public opaque-dev/opaque-demo repository. Internal
dogfood, research and evidence have a separate private home.
Do not copy private history, configuration, research or runtime records here.

Preserve transactional revocation, durable single-use consumption and explicit unknown
outcomes when changing interfaces. Keep storage drivers out of new wire contracts.
Never commit credentials, keys, local environment/browser state, generated binaries
or raw session artifacts. Use exact source/destination refspecs when pushing branches.

# Public content

Every public page answers one user question. Every section must add a concrete
product behavior, necessary prerequisite, evidence, or next action. Identify that
purpose before editing; remove sections that repeat another section's job.

- Lead with what the user can do and show a real command, interface, or workflow.
- Keep one product statement per entry page; avoid stacked slogans, generic persona
  cards, and internal acquisition or evaluation methodology in visitor copy.
- Tie security claims to the applicable operation, deployment boundary, version,
  and public evidence. Distinguish implementation, test, and customer evidence.
- Label illustrations and synthetic results. Never invent metrics, testimonials,
  customers, certifications, or successful executions.
- State release availability where a capability is introduced. Keep protocol and
  configuration depth in reference pages, with descriptive links from the overview.
- For homepage prose, aim for 300 words; commands and necessary scope labels may
  exceed that. Reference length follows the user's task, not a marketing template.
- Review the rendered page for repetition, readable hierarchy, working links and
  mobile navigation. Shorter copy must not erase prerequisites or material limits.
