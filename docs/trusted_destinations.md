# Trusted Egress Destinations Specification

## 1. Criterion for Trusted Egress Exemption

An external destination domain qualifies for exemption from automated egress blocking (`unless: domain_allowlist`) if and only if it satisfies both clauses of the following criterion:

> **The destination is non-user-generated AND an attacker cannot read its request logs.**

### Security Rationale
1. **Non-User-Generated:** The platform does not allow arbitrary unauthenticated or untrusted users to upload, publish, or modify content where query parameters, request bodies, or paths could reflect attacker-controlled data back to an attacker.
2. **Attacker-Inaccessible Request Logs:** The destination infrastructure does not expose HTTP access logs, query parameters, referrers, or telemetry to third parties or arbitrary users, preventing side-channel exfiltration via outbound URL queries or headers.

---

## 2. Curated Trusted List

The following 9 domains satisfy the criterion and are approved for flow rule `unless` exemption evaluation:

| Domain | Justification Line |
|---|---|
| `developer.mozilla.org` | Curated MDN web documentation maintained strictly by Mozilla staff; no user-generated query reflection or public request logging. |
| `www.rfc-editor.org` | Official IETF RFC standards repository; static editorial publication without user-controlled content or public access logs. |
| `go.dev` | Official Go language documentation and specifications managed by the Go team; static and non-user-generated with private logs. |
| `kubernetes.io` | Official Kubernetes project documentation maintained by CNCF committers; review-gated static content with private logs. |
| `docs.aws.amazon.com` | Official AWS cloud documentation authored exclusively by Amazon technical writers; no arbitrary user publishing or public logs. |
| `docs.djangoproject.com` | Official Django framework documentation maintained by the Django Software Foundation; static, curated, and private logs. |
| `nvd.nist.gov` | National Vulnerability Database operated by NIST; authoritative federal vulnerability data with strictly controlled publication and private logs. |
| `registry.npmjs.org` | Official npm registry metadata API; package metadata is published via authenticated release pipeline, and package lookup query logs are internal to npm/GitHub infrastructure. |
| `crates.io` | Official Rust package registry API operated by the Rust Foundation; package metadata is immutable per version and web logs are private to infrastructure operators. |

---

## 3. Explicitly Excluded Domains

The following domains are explicitly **EXCLUDED** from the trusted exemption list because they violate the criterion (user-generated or attacker-hostable):

| Domain Pattern | Disqualification Reason (Violation of Criterion) |
|---|---|
| `stackoverflow.com` | **User-generated:** Any user can post questions, answers, and comments; URL paths or parameters can link to or reflect user-controlled tracking markers. |
| `github.com` | **User-generated & Attacker-hostable:** Arbitrary users can host repositories, issues, discussions, gists, and releases, allowing attackers to host payloads or receive exfiltration data directly. |
| `raw.githubusercontent.com` | **User-generated & Attacker-hostable:** Serves raw contents of arbitrary user-owned repositories and branches; attackers can host exfiltration drops or retrieve staged payloads. |
| `*.readthedocs.io` | **User-generated & Attacker-hostable:** Open hosting service where any user can register and host project documentation; attackers can deploy malicious doc pages or track inbound requests. |
| `*.s3.amazonaws.com` | **Attacker-hostable & User-controlled:** Any AWS account can create public S3 buckets; attackers can configure bucket logging or API gateways to capture exfiltrated query parameters or uploaded files. |
