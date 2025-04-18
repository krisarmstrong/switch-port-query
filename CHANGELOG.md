# Changelog

## [1.1.0] - 2025-04-18
- Renamed project to `SwitchPortQuery`
- Added contact email to `CODE_OF_CONDUCT.md`
- Added comprehensive test suite (`tests/test_switch_port_query.py`)
- Added `.gitignore` for standard exclusions
- Enhanced interactive mode with input validation
- Improved error handling for specific SNMP exceptions
- Cached `SnmpEngine` for better SNMP performance
- Updated `version_bumper.py` to auto-update `CHANGELOG.md`
- Provided ZIP bundle for release
- Ensured robust `KeyboardInterrupt` handling

[1.1.0]: https://github.com/yourusername/switch-port-query/releases/tag/v1.1.0

## [0.1.0] - 2025-04-18
- Initial release: merged status and find commands into single CLI
- Added interactive mode
- Integrated SNMP queries with pysnmp
- Implemented logging with rotating file handler
- Added unit tests and CI configuration

[0.1.0]: https://github.com/yourusername/switch-port-query/releases/tag/v0.1.0