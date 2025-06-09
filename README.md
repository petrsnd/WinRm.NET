[![build test and publish](https://github.com/CodyBatt/WinRm.NET/actions/workflows/build-publish.yml/badge.svg)](https://github.com/CodyBatt/WinRm.NET/actions/workflows/build-publish.yml)

# WinRm.NET
.NET implementation of WinRM client

The driver for this project is the ability to run remote Windows commands securely from Linux. This is currently work-in-progress. Requests run directly in .NET without any dependency on PowerShell. It should be possible to authenticate using NTLM or Kerberos from Windows or Linux without needing to be joined to a domain.
