# Contributing

Contributions are welcome. Please read the following guidelines before submitting.

## Issues

- Search existing issues before opening a new one
- Include browser version and OS when reporting bugs
- Provide steps to reproduce the issue
- Attach screenshots if applicable

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/description`)
3. Make your changes
4. Test in multiple browsers (Chrome, Firefox, Safari)
5. Commit with clear messages
6. Push to your fork
7. Open a pull request against `main`

## Code Standards

- Vanilla JavaScript only — no external dependencies
- User input MUST be validated, sanitized, and escaped
- Follow existing code style and naming conventions
- Keep functions focused and well-documented
- Test drag-and-drop, import/export, and metadata editing

## Data Updates

When updating ATT&CK, CAPEC, or CWE data:

1. Download ATT&CK STIX Bundle source files to `frameworks/ATTCK/DOMAIN.json` ("ENTERPRISE", "MOBILE" & "ICS").
Download CAPEC XML Definitions to `frameworks/CAPEC/DOMAINs.xml` & `frameworks/CAPEC/MECHANISMS.xml`.
Download CWE XML Definitions to `frameworks/CWE/HARDWARE.xml` & `frameworks/CWE/SOFTWARE.xml`.
2. Run extraction scripts in `scripts/`
3. Verify JSON output is valid
4. Test the application with new data

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
