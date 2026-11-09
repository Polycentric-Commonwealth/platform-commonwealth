# Commonwealth platform

The reference platform for the **Commonwealth**, the global layer of the [Polycentric Commonwealth](https://github.com/Polycentric-Commonwealth/foundation): the charter and Commonwealth law, the Citizens' and States' Chambers, the Commons Fund and dividend settlement, the Audit Office, the uniqueness registry, and attestation of member instances.

It holds the least personal data of any layer. It sees States, totals and signed acts, never individuals, and it is built so that the Commonwealth cannot compile a database of people. Its code is open, and anyone can run a mirror or a test instance.

## Planned first stage

- Attest Regions and States, and publish the Commonwealth's instance description and trust anchor.
- Settle dividends from States' eligibility counts, and receive payment confirmations.
- Run eligibility audits through an Audit Office workspace, with field checks recorded by auditors.
- Run the uniqueness registry and publish the uniqueness configuration ([federated identity](https://github.com/Polycentric-Commonwealth/foundation/blob/main/specs/federated-identity.md)).
- Keep a witnessed public ledger, and witness the logs of other instances.

Until this exists, `pcstate devcommonwealth` in the State platform is a stand-in for testing.

The full list of planned modules is in the [platforms plan, section 4](https://github.com/Polycentric-Commonwealth/foundation/blob/main/docs/design/platforms-plan.md#4-commonwealth-platform).

## Status

Not started. The first stage is planned in the [platforms plan](https://github.com/Polycentric-Commonwealth/foundation/blob/main/docs/design/platforms-plan.md#10-build-roadmap-and-open-questions). It will use the same stack and shared [foundation](https://github.com/Polycentric-Commonwealth/foundation) library as the [State platform](https://github.com/Polycentric-Commonwealth/platform-state): Go, SQLite or PostgreSQL, and server-rendered HTML ([decision 0004](https://github.com/Polycentric-Commonwealth/foundation/blob/main/decisions/0004-technology-stack.md)).

New here? Start with the [ten-minute explainer](https://github.com/Polycentric-Commonwealth/foundation/blob/main/docs/explainer.md). To help, see [contributing](https://github.com/Polycentric-Commonwealth/foundation/blob/main/CONTRIBUTING.md).

## Licence

Code is licensed under the [Apache License 2.0](LICENSE). See the foundation repository for the project's licensing decisions.
