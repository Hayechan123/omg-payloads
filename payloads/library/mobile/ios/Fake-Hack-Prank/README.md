# Fake-Hack-Prank

**Author:** hayechan123
**Target:** iOS (iPhone/iPad) & Android
**Category:** Prank
**Version:** 1.0

## Description

Opens a dramatic "fake hacking" screen in the browser showing the victim's **real IP address** and **approximate location** (city/region via IP geolocation). Includes a scary 30-second countdown, fake data-exfiltration log, and blinking red UI — all in Korean.

> **Note:** This is a visual prank only. No data is actually collected or transmitted.

## Setup

### 1. Host the HTML page

Upload `fake-hack.html` to any static hosting service:

- **GitHub Pages** — push to a public repo and enable Pages
- **Netlify Drop** — drag the file to [netlify.com/drop](https://netlify.com/drop)
- **Vercel** — `npx vercel` in the folder

Copy the resulting public URL.

### 2. Update the payload

In `payload.txt` (iOS) or `../android/Fake-Hack-Prank/payload.txt` (Android), replace:

```
STRING PASTE_YOUR_URL_HERE
```

with your hosted URL, e.g.:

```
STRING https://yourname.github.io/fake-hack
```

### 3. Flash to O.MG Cable and plug in

- **iOS:** Requires Lightning-to-USB-A or USB-C camera adapter
- **Android:** Plug directly; timing in `DELAY` lines may need tuning per device

## What the victim sees

1. Their real IP address
2. Their city, region, and country (from IP geolocation)
3. Their ISP/carrier name
4. A 30-second countdown to "data transfer complete"
5. A scrolling fake log of stolen files

## Legal

For use on your own devices or with explicit permission only. Educational and entertainment purposes.
