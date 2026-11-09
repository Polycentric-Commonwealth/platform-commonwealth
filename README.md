# Commonwealth platform

The reference platform for the **Commonwealth**, the global layer of the [Polycentric Commonwealth](https://github.com/Polycentric-Commonwealth/foundation). It attests member Regions and States, runs the Commons Fund that pays every person an equal dividend, carries out the Audit Office's eligibility audits, keeps the uniqueness registry, and publishes every act in a witnessed public ledger.

It holds the least personal data of any layer. It sees States, totals and signed acts, never a register of people. The only personal data it ever receives is an audit sample, shown to auditors for the field check and erased once the finding is issued. Its code is open, and anyone can run a mirror or a test instance.

New here? Start with the [ten-minute explainer](https://github.com/Polycentric-Commonwealth/foundation/blob/main/docs/explainer.md).

## What it does

| Area | Who uses it | What it does |
| --- | --- | --- |
| Overview, Members | Everyone | Member Regions and States, and when each was attested |
| Dividends | Everyone | Each period: the pool, the dividend per person, and each State's count, settlement, payment and audit |
| Audits, Uniqueness | Everyone | Every audit's result, and how many uniqueness tokens each State has registered and how many conflicts are open |
| Public ledger | Everyone | Every record the Commonwealth has issued, checked against its signature and the witnesses' cosignatures |
| Commons Fund | Treasurers | Settle a period: divide its pool equally among everyone counted and send each State its settlement |
| Members | Members office | Attest a Region or State from its signed description, after confirming its key fingerprints with it; suspend and reinstate members |
| Audit Office | Auditors | Record whether each sampled person was found in the field, then issue the finding |
| Officials | Officials | Accounts, roles and the activity log |
| `/pc/inbox`, `/pc/ledger/…`, `/pc/uniqueness/config`, `/.well-known/pc-instance` | Other instances | The [protocol](https://github.com/Polycentric-Commonwealth/foundation/tree/main/specs) endpoints |

### How a period works

1. Member States report eligibility counts. Each count must come from a State the Commonwealth or one of its member Regions attested, and only one per State per period is accepted.
2. Every count is audited at once: the Audit Office sends a random sample request, the State opens the sampled entries, and the platform checks them against the committed list.
3. A treasurer settles the period with the pool to distribute. The dividend per person is the pool divided by everyone counted, rounded down to a millionth of an XCU; the remainder stays in the fund. Counts arriving afterwards are refused.
4. Each State pays its residents and confirms the total.
5. Auditors record whether each sampled person was found. The finding is then issued: passed, or a repayment of three times the estimated overpayment. The sampled people's details are erased.

## Deploy it

With [Go](https://go.dev/dl/) 1.24 or later:

```sh
go build ./cmd/pccommonwealth

# 1. Create the deployment. It prints the first admin's password and the trust anchor members pin.
./pccommonwealth init -dir /srv/pccommonwealth -instance commonwealth.example -name "Commonwealth" \
  -base-url https://commonwealth.example/ -listen :8443 -tls-cert cert.pem -tls-key key.pem

# 2. Run it.
./pccommonwealth serve -dir /srv/pccommonwealth
```

Then attest each Region or State on the **Members** page: paste its `description.json`, read the key fingerprints to its officials, and give it the attestation, which a State adds with `pcstate attestation add`.

Other commands:

- `pccommonwealth anchor -dir DIR` prints the trust anchor again.
- `pccommonwealth official add|reset|disable|list -dir DIR` manages officials' accounts. Roles are `admin`, `members`, `treasurer` and `auditor`.
- `pccommonwealth uniqueness deal -dir DIR -epoch 1 -threshold 2 -operator op1.example -operator op2.example -operator op3.example -out shares` creates a uniqueness key split among the operators, publishes the configuration and writes each operator's secret share. Stop the server first, deliver the shares securely, then delete them.

Init flags: `-witness` (repeatable) and `-witness-threshold` choose who cosigns the Commonwealth's ledger, normally member instances; `-peer ID=https://host:port` reaches an instance at another address; `-ca-file` trusts extra certificates; `-multiplier` changes the audit repayment multiplier.

## How it is built

The same stack as the [State platform](https://github.com/Polycentric-Commonwealth/platform-state): Go with the [foundation](https://github.com/Polycentric-Commonwealth/foundation) library, SQLite through a pure-Go driver, and server-rendered HTML with no JavaScript and a strict Content Security Policy.

| Package | Role |
| --- | --- |
| [`internal/commonwealth`](internal/commonwealth/) | The core: attesting members, accepting counts, settling periods, audits, the uniqueness registry and the ledger |
| [`internal/store`](internal/store/) | The database: records, members, periods and counts, audits, uniqueness tokens, the ledger and officials |
| [`internal/web`](internal/web/) | Public pages and the officials' workspace |
| [`internal/deploy`](internal/deploy/) | Deployments: configuration, keys, restoring members and refreshing their descriptions |
| [`cmd/pccommonwealth`](cmd/pccommonwealth/) | The command |

The officials' accounts, sessions, ledger storage and page styles are shared in shape with the State platform. Once the Region platform needs them too, they will move into a shared package.

## Not yet built

- **The Commons Fund's income:** the pool is entered by a treasurer. Rent and carbon-fee reporting from States, and the charter formula, come next ([platforms plan](https://github.com/Polycentric-Commonwealth/foundation/blob/main/docs/design/platforms-plan.md#4-commonwealth-platform)).
- **Repayments:** findings state what a State owes, but nothing yet deducts it from the next settlement.
- **Uniqueness operators:** the configuration is published, but no platform runs an operator yet; Regions are the natural hosts.
- **Distributed key generation** for the uniqueness key, instead of a dealer.
- **The other Commonwealth modules:** charter and law registry, legislative workspace, sortition, Charter Court docket, enforcement, inspection, statistics.

## Licence

Code is licensed under the [Apache License 2.0](LICENSE). See the foundation repository for the project's licensing decisions.
