### Update changelog with 2026-02-16 cleanup details (HEAD -> main, origin/main, gitea/main)
>Mon, 16 Feb 2026 12:23:34 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Clean repository structure and align docs with implementation
>Mon, 16 Feb 2026 12:21:46 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Add minimal UniFi API client
>Mon, 16 Feb 2026 11:46:54 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Fix duplicated VRF creation
>Mon, 16 Feb 2026 10:58:43 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### test push (tag: v1)
>Thu, 12 Feb 2026 09:50:19 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### test push
>Thu, 12 Feb 2026 09:49:53 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Update issue templates
>Thu, 12 Feb 2026 09:31:40 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: GitHub (noreply@github.com)




### Complete documentation overhaul
>Thu, 12 Feb 2026 08:45:56 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Rewrite README.md with all new features (community specs, cleanup, sync loop)
- Improve .env.example with grouped sections and safety warnings
- Add CHANGELOG.md with full version history
- Add docs/ directory: configuration, cleanup guide, device specs, architecture,
  troubleshooting, FAQ
- Create Gitea wiki (6 pages): Home, Quick Start, Config, Cleanup,
  Troubleshooting, Architecture

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Add unit tests, CI/CD, and code cleanup
>Thu, 12 Feb 2026 08:34:05 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Add pytest test suite (48 tests): device helpers, community specs, cleanup
- Add Gitea Actions CI workflow (lint, test, Docker build)
- Make threading limits env-configurable (MAX_CONTROLLER/SITE/DEVICE_THREADS)
- Update .gitignore with client key files
- Remove obsolete README-old.md

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Add community device specs, NetBox cleanup, auto-create device types, and sync loop
>Thu, 12 Feb 2026 08:19:02 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Integrate netbox-community/devicetype-library (173 Ubiquiti devices) with
  bundled JSON specs for interfaces, console/power ports, PoE, weight, airflow
- Add generic _sync_templates() for interface/console-port/power-port templates
- Add NetBox cleanup functions (NETBOX_CLEANUP env var): stale devices,
  garbage interfaces, orphan IPs, orphan cables, unused device types
- Auto-populate new device types from community specs at creation time
- Add SYNC_INTERVAL env var for continuous sync loop (default: run once)
- Update Dockerfile to include data/ directory

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Add DHCP auto-discovery from UniFi network configs
>Wed, 11 Feb 2026 16:48:04 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

Automatically extract DHCP-enabled subnets from UniFi's network
configuration API and merge with manually configured DHCP_RANGES.
Falls back to Legacy API when Integration API lacks DHCP fields.
Controlled via DHCP_AUTO_DISCOVER env var (default: true).

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### update
>Wed, 11 Feb 2026 16:42:05 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Remove unused UniFi classes, fix tag race condition, anonymize and secure repo
>Wed, 11 Feb 2026 16:26:35 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Delete 5 unused resource classes (ApGroups, PortConf, RadiusProfile, Setting, UserGroup)
- Fix TOCTOU race condition in ensure_tag() using double-check locking
- Add .claude/ to .gitignore to prevent credential leaks
- Anonymize real IP ranges in docs with RFC 1918 examples

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Update all documentation to reflect current features
>Wed, 11 Feb 2026 12:31:13 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Rewrite README.md with complete config reference, feature docs,
  supported hardware table, threading model, and quick start guide
- Add threading config to .env.example
- Improve site_mapping.yaml comments

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Add device type specs database and sync interface templates from UniFi model specs
>Wed, 11 Feb 2026 12:25:13 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Add UNIFI_MODEL_SPECS dictionary with ~40 UniFi models mapping to part numbers,
  u_height, port definitions (type/count), and PoE budget
- Add ensure_device_type_specs() to sync device type metadata and interface templates
- Fix USPM24P mixed port conflict with {n+offset} pattern (Port 1-16 = 1G, 17-24 = 2.5G)
- Fix devicetype_id filter bug (correct param: device_type_id) that caused cross-contamination
- Serialize template operations with lock to prevent concurrent API races
- Replace old port_table template creation with spec-driven sync
- Idempotent: skips sync when templates already match, processes each type once per run

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### update
>Wed, 11 Feb 2026 07:52:52 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### update
>Wed, 11 Feb 2026 07:49:24 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### update
>Wed, 11 Feb 2026 07:29:23 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Cable sync, offline cleanup, stale devices, and reliability improvements
>Wed, 11 Feb 2026 06:56:55 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Fix cable sync: fetch uplink data from device detail API (Integration API
  list endpoint returns empty uplink), create eth0 for APs without wired ports,
  O(1) UUID lookup for upstream devices, filter wireless/virtual interfaces
- Remove cables from offline devices automatically
- Mark stale devices (removed from UniFi) as offline in NetBox
- Add feature toggles: SYNC_VLANS, SYNC_WLANS, SYNC_CABLES, SYNC_STALE_CLEANUP
- Fix silent exceptions: add logging to 5 bare except/pass blocks
- Fix tag cache race condition: only cache non-None values
- Add unifi_last_seen custom field with epoch-to-ISO conversion
- Enhanced radio descriptions with band, channel, TX power
- Docker: add healthcheck and restart policy

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### update
>Tue, 10 Feb 2026 23:01:15 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### update
>Tue, 10 Feb 2026 22:50:11 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### u
>Tue, 10 Feb 2026 18:33:11 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### UPDATE
>Tue, 10 Feb 2026 18:19:11 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### update
>Tue, 10 Feb 2026 14:11:26 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Add comprehensive UniFi to NetBox sync: state, firmware, VLANs, SSIDs, cables
>Tue, 10 Feb 2026 13:39:46 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

New sync features:
- Device state (ONLINE/OFFLINE) synced to NetBox status (active/offline)
- Firmware version, uptime, MAC synced to custom fields (auto-created)
- VLANs synced from UniFi networks to NetBox (with VLAN groups per site)
- WiFi SSIDs synced to NetBox wireless LANs (with auth type mapping)
- Uplink cables created between devices (topology from UniFi uplink data)
- Refactored tag logic to use ensure_tag() helper
- NetworkConf and WlanConf now support Integration API endpoints

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Sync UniFi device ports and radio interfaces to NetBox
>Tue, 10 Feb 2026 13:32:34 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Creates/updates physical port interfaces (name, type, speed, PoE, enabled)
- Creates/updates wireless radio interfaces for APs
- Upsert logic: matches by device_id + name, only updates if changed
- Supports both Integration API and legacy API data formats
- Toggle with SYNC_INTERFACES env var (default: true)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Check IP changes on existing devices and auto-add zabbix tag
>Tue, 10 Feb 2026 13:20:56 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

- Existing devices now get IP checked/updated instead of being skipped
- Detects IP changes and updates NetBox accordingly
- Auto-adds "zabbix" tag to all devices (creates tag if missing)
- Removed vrf_ prefix from VRF names
- IP addresses created with status "offline"

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Remove vrf_ prefix from VRF names and set IP status to offline
>Tue, 10 Feb 2026 13:10:12 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)

VRF lookup now matches site name directly without legacy "vrf_" prefix.
IP addresses created in NetBox now get status "offline" instead of "active".

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>



### Update
>Tue, 10 Feb 2026 09:28:15 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Fix duplicate VRF creation
>Tue, 10 Feb 2026 09:08:02 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Fix duplicate VRF creation
>Tue, 10 Feb 2026 09:06:43 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Document serial handling modes
>Tue, 10 Feb 2026 08:58:12 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Remove IDE config and Python bytecode artifacts
>Tue, 10 Feb 2026 08:30:27 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Update unifi2netbox based on patch
>Tue, 10 Feb 2026 08:24:20 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Handle duplicate roles in NetBox
>Tue, 10 Feb 2026 08:19:32 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Update README with new env config
>Tue, 10 Feb 2026 08:16:51 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Prepare code for UniFi API
>Tue, 10 Feb 2026 07:58:22 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Prepare code for UniFi API
>Mon, 9 Feb 2026 22:11:37 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Prepare code for UniFi API
>Mon, 9 Feb 2026 22:10:21 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Prepare code for UniFi API
>Mon, 9 Feb 2026 22:09:11 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Prepare repo for UniFi API
>Mon, 9 Feb 2026 22:06:35 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Enable UniFi API integration
>Mon, 9 Feb 2026 22:01:13 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### Fix UniFi API integration
>Mon, 9 Feb 2026 21:53:15 +0100

>Author: Patrick Lind (19758127+patricklind@users.noreply.github.com)

>Commiter: Patrick Lind (19758127+patricklind@users.noreply.github.com)




### feat: implement UniFi API module with site mapping and improved session management
>Sat, 21 Jun 2025 14:18:57 -0400

>Author: mrzepa (54753272+mrzepa@users.noreply.github.com)

>Commiter: mrzepa (54753272+mrzepa@users.noreply.github.com)




### licsense declared in README.md, but LICENSE file missing in REPO
>Tue, 15 Apr 2025 06:53:32 +0000

>Author: PAEPCKE, Michael (git@paepcke.de)

>Commiter: PAEPCKE, Michael (git@paepcke.de)




### Delete config/config.yaml
>Fri, 24 Jan 2025 13:47:55 -0500

>Author: mrzepa (54753272+mrzepa@users.noreply.github.com)

>Commiter: GitHub (noreply@github.com)




### fix files
>Fri, 24 Jan 2025 13:44:42 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




### updated README.md
>Thu, 23 Jan 2025 08:51:39 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




### updated README.md
>Thu, 23 Jan 2025 08:50:24 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




### updated README.md
>Thu, 23 Jan 2025 08:49:51 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




### updated README.md
>Thu, 23 Jan 2025 08:48:51 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




### initial commit
>Thu, 23 Jan 2025 08:43:36 -0500

>Author: mark (mark@source44.net)

>Commiter: mark (mark@source44.net)




