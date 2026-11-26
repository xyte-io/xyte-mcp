# Changelog

## 0.5.3

- Catalog regenerated from the hub release of 2026-11-26 (DEV-8305, DEV-7341, DEV-8208):
  - Partner Get Devices / Get Device Info: `created_at` and `claimed_at` on every device.
  - Organization API: new Move Device to Edge (`POST /core/v1/organization/edges/devices/:device_id/move`).
  - Organization Get Devices / Get Device / Claim Device: `merged_effective_status_updated_at`.

## 0.5.2

- Spaces: the `room_status` filter is available (catalog regenerated from hub, PR #65, DEV-8207).
- Restores the npm `latest` tag to the newest release. 0.5.0 was published after 0.5.1, so `latest` pointed at 0.5.0 instead of 0.5.1.
