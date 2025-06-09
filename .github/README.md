# Trustify
[![BSD-3 License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](../LICENSE.md)
[![Windows 11](https://img.shields.io/badge/Windows-11%20-007bb8.svg?logo=Windows)](#)


Trustify is a command-line tool for creating (and deleting) inbound Active Directory forest trusts with TGT delegation enabled using native Windows LSA APIs.

## Usage

```bash
Trustify.exe [create|delete] ...
```

### Create Trust

```bash
Trustify.exe create [target] [sid] [dns] [netbios] [password]
```

- `target`: The remote domain where the trust is created (e.g. `domain.com`)
- `sid`: SID of the trusted domain (e.g. `S-1-5-21-...`)
- `dns`: DNS name of the trusted domain
- `netbios`: NetBIOS name of the trusted domain
- `password`: Trust password (plaintext)

### Delete Trust

```bash
Trustify.exe delete [target] [sid]
```

- `target`: The remote domain where the trust is deleted
- `sid`: SID of the trusted domain to delete

### Usage Example

Create an inbound forest trust in target.local from the domain attacker.local:
```cmd
Trustify.exe create target.local S-1-5-21-1556913138-1403956553-584833181 attacker.local ATTACKER Summer2025!
```

Delete the trust created above:
```cmd
Trustify.exe delete target.local S-1-5-21-1556913138-1403956553-584833181
```

## Requirements

- Windows OS
- Run as a user with sufficient privileges (Membership in Enterprise Admins, Domain Admins in root domain, or Incoming Forest Trust Builders)
- .NET Framework or .NET-compatible runtime for building/running

## Build Instructions

To compile using Visual Studio:

1. Open the `.sln` file in Visual Studio.
2. Select build configuration (`Release` or `Debug`).
3. Build the solution.

Or compile with `dotnet` CLI:

```bash
dotnet build Trustify.csproj
```
