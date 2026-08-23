# Policy reference

Kovert configuration is strict TOML with `version = 1`. Unknown fields and
unknown enum values fail validation.

## Daemon

`[daemon]` supports:

| Field | Meaning |
|---|---|
| `socket_path` | Absolute Unix-socket path |
| `state_path` | Absolute SQLite state path |
| `dry_run` | Plan and audit actions without changing the host |
| `poll_interval` | Human duration such as `5s` or `1m` |
| `command_timeout` | Maximum adapter/program runtime |
| `event_buffer` | Bounded event-channel capacity, minimum 16 |
| `socket_group` | Local group allowed to use the control socket |
| `allowed_executables` | Absolute custom-program allowlist |
| `managed_processes` | Exact `/proc/<pid>/comm` names permitted for signals |
| `desktop_notifications` | Use `notify-send` in addition to journald |

## Rule controls

Each `[[rules]]` table has `id`, optional `description`, `enabled`, `priority`,
`cooldown`, `sustain_for`, `once_per_boot`, `on_sensor_failure`, `trigger`,
optional `when`, and one or more `actions`.

`on_sensor_failure` is `alert` by default. `ignore` suppresses the event.
`fail_closed` permits only vault locking, enabling network isolation, and mode
changes from that rule.

## Triggers

Trigger `type` values:

- `tick`
- `file`: `path`, optional `operations`, optional `recursive`
- `wifi_changed`: optional `ssid`, `bssid`, `connected`
- `network_changed`: optional `interface`, `online`, `vpn`
- `usb`: optional `action`, `vendor_id`, `product_id`, `serial`
- `mount`: optional `action`, `path`
- `process`: optional `name`, `running`
- `service`: optional `name`, `active`
- `port`: optional `port`, `open`, `protocol`
- `session`: optional `state`, `user`, `remote`
- `power`: optional `on_ac`, `battery_below`, `lid_closed`
- `hotkey`: configured hotkey `name`
- `integrity_failure`: optional `component`
- `manual`: exact event `name`
- `sensor_failure`: optional sensor name
- `all`, `any`, `not`
- `sequence`: at least two `steps` and a non-zero `within` duration

File operations are `create`, `modify`, `rename`, `delete`, `access`, `metadata`
and `other`. Device actions are `added`, `removed` and `changed`. Protocols are
`tcp` and `udp`.

## Conditions

Condition `type` values:

- `all`, `any`, `not`
- `time_window`: `start`, `end`, optional `outside`, optional `weekdays`
- `wifi`: optional `ssid`, `bssid`, `connected`
- `network`: optional `online`, `interface`, `vpn`
- `mode`: `name`
- `path_exists`: absolute `path`, `exists`
- `mounted`: absolute `path`, `mounted`
- `process`: `name`, `running`
- `service`: `name`, `active`
- `port`: `port`, `open`, optional `protocol`
- `session`: optional `state`, `user`, `remote`
- `power`: optional `on_ac`, `battery_below`, `lid_closed`
- `sensor_healthy`: `sensor`, `healthy`

Time windows use the machine's local timezone and handle overnight ranges such
as `22:00` to `06:00`.

## Actions

Action `type` values:

- `lock_vault` and `unlock_vault`: configured `vault`
- `unmount`: absolute `path`
- `network_isolation`: `enabled`
- `interface_state`: validated `interface`, `up`
- `service`: unit `name`, `state` (`start`, `stop`, `restart`)
- `terminate_process`: allowlisted `process`, optional `signal`
- `notify`: `title`, `message`, optional `urgency`
- `capture_evidence`: absolute `paths`, absolute `destination`
- `set_mode`: configured `mode`
- `exec`: allowlisted absolute `executable`, argument array, optional SHA-256,
  optional uppercase environment map

No action accepts a command-line string or invokes `/bin/sh`.

## Emergency sequences

Each `[[hotkeys]]` item contains `name`, absolute `/dev/input/event*` `device`,
ordered `sequence`, and `within`. Supported names include letters, digits,
modifiers, arrows, navigation keys and F1 through F12. Prefixes such as
`KEY_LEFTCTRL` are accepted.

