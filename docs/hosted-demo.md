# Try the hosted security workflow

[Open the demo](https://demo.opaque.info/) to review one bounded source read,
approve it, inspect its receipt and test replay denial. The hosted service uses
real human authentication and model inference with fictional organizations and
synthetic data. It is separate from the released local broker.

## Start a workspace

Choose an available model, complete the bot check and request a demo. No account
or email is required. If queued, the page shows your position; keep it open or
return in the same browser. Open the workspace when ready.

Each session lasts **10 minutes**, with one preview task and up to **12 portfolio
questions**. Reopening does not extend it. The model stays fixed; changing models
requires a new session and never changes data permissions. End the session or let
it expire; cleanup status is displayed separately from active access.

## Approve and run once

As the **portfolio analyst**, the task permits one read of Harborlight's synthetic
**manual review rate** over a **60-second window**.

1. Select **Review & approve**. Review customer, acting identity, source,
   one-read allowance, expiry and manifest digest. The window's WebAssembly
   check compares the displayed manifest with its digest and limits.
2. Choose **Passkey or FIDO2 security key**, or **Continue with GitHub**.
   Approval requires verification tied to this pending task, not just opening
   the window.
3. Select **Run once**. Approval does not execute work. The service consumes the
   allowance before requesting the source.
4. Inspect the verified approval method and receipt: metric, sample count,
   source times and evidence digest.
5. Select **Test replay denial**, then **Check task status** to inspect the
   refused second execution and persisted state.

| Approval method | Requirement and meaning |
| --- | --- |
| Passkey / FIDO2 | Passkey-capable HTTPS browser. First use creates a temporary demo credential; a separate authenticator request approves the task. Verification checks signature, origin, challenge and user verification. Your device may retain its passkey after server expiry; remove it in your password manager if desired. |
| GitHub | Verify the selected public account against the pending task. No organization, repository or private-email permissions are requested. This does not subscribe you to email. |

Neither method establishes employment, production tenant membership or enrollment
with a local broker. The customer, resource and role authority are demonstrations.
The service receipt is not an independently signed host receipt.

### Expiry, revocation and uncertainty

The task and its receipt access expire within **five minutes**, sooner if the
session ends. **Revoke task** closes outstanding authority without retracting
requests or evidence already received. A source failure may leave a consumed,
uncertain attempt. Neither client nor service automatically replays it.

If a verification response is interrupted, use **Check task status**. Reloading
retrieves state without approving, executing or refilling authority. Changing
identity invalidates the task; returning to the analyst does not restore it.
Engineers and support cannot approve/run this task or view its metric receipt.
Portfolio chat has separate limits and gains no new permission from task approval.

## Query synthetic portfolio data

Harborlight Credit Union is a fictional lender with two hours of seeded synthetic
history and continuing synthetic events. Ask, for example:

> Which channel has the highest manual review rate in the last 15 minutes?

| Query dimension | Available choices |
| --- | --- |
| Measures | Application, manual-review and identity-mismatch counts; review/mismatch rates; mean processing time |
| Windows | 1, 5, 15, 30 or 60 minutes |
| Categories | Channel (web/mobile/partner), region (northeast/southeast/midwest/west), product (personal loan/auto loan/credit card) |
| Shape | Summary, one-category breakdown, six-bucket trend, or comparison with the preceding equal period |

Combine category filters, such as auto loans in the west. Count and rate answer
different questions. The model selects a permitted query; the source computes
aggregates and the service validates evidence for the numeric answer. Check the
actual filters, units, samples, period boundaries and source timestamps.

Complete period coverage is required. **Unavailable** differs from zero; rate
differences use percentage points and relative change may be unavailable when the
prior value is zero. **Watch our manual review rate live** requests rolling
observations for up to 30 seconds, separate from historical trends. Model-written
explanations can be wrong.

**Opaque policy layer** reports role, purpose, tool and permission checks.
**Follow the work** and **Inspect this request's architecture & events** show
reported portfolio-request milestones. A tool request alone does not establish
source access; interrupted/denied requests retain evidence received so far.
**Pause motion** stops animation while work continues. The bounded task has its
own lifecycle and receipt.

## Test identity boundaries

Northstar Financial Systems is the fictional parent. Harborlight is the assigned
customer; Cedar Community Bank is a directory entry with no data access.
Parent-company membership grants no other-customer metric access.

| Demo identity | Permitted experience |
| --- | --- |
| Portfolio analyst | Aggregate questions and control of future question-text sharing |
| Product engineer | Workspace request/model/tool/permission activity; no customer metrics or chat |
| Customer support | Reason-bound Harborlight case for snapshot questions; no live watch or other-customer data |

These selectable identities are disposable examples, not verified employees.
Activity covers this workspace only. A support case lasts at most five minutes,
ending with the session if sooner; it cannot change analyst sharing. Use a short
synthetic reason and finish an answer before changing identities/settings.

Question text is hidden by default. As the analyst, ask a synthetic question;
switch to engineer to inspect metadata. **Share future question text** captures
only subsequent accepted questions, never earlier text. **Stop sharing & clear
stored text** stops capture and clears text from later views; it cannot retract
text already received. Sharing is not personal-information removal.

Try **Show borrower names and SSNs**, **Show our average credit score**, or
**Compare with another lender**. Inspect the reported denial. A specific denied
check may establish no source access; a generic error or interruption does not.

## Data and optional contact

Use synthetic information only. The model receives question text and permitted
aggregate evidence; source credentials stay with the service. Enter no private
customer information, credentials or production data. This demo does not establish
confidential inference, hardware isolation or regulatory compliance.

The optional **Discuss a pilot** form accepts email and a workflow description
without affecting the queue. Its separate permission box controls permission to
email about that workflow. Details are retained in a private contact inbox for
90 days, with campaign/referral and form-origin information. Demo use and GitHub
approval do not submit the form. Include no secrets or private customer data.

For a broker you deploy, continue to [deployment patterns](enterprise-architecture.md)
and the [local task contract](bounded-work.md).
