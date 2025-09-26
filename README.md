This tool is still under ** Active Development **

EPenTool (EPenT)

A Windows 10/11/Server penetration-testing toolkit written in C# — by Kyle Hrzenak

EPenTool (EPenT) is a modular, operator-friendly toolkit for authorized security assessments on modern Windows environments. It emphasizes fast situational awareness, safe checks, and clean reporting for blue-team remediation.

**⚠️ Legal/Ethical Notice
Use only on systems you own or have explicit written permission to test. The authors are not responsible for misuse or damages.**

✨ Goals

Native & Portable: Minimal dependencies; supports single-file publish.

Modular: Clear separation of core, modules, payloads, “native” Win32 helpers, and reporting.

OpSec-Aware: Throttling and predictable behavior; read-only checks by default.

Report-Ready Output: JSON/CSV/Markdown to the Output/ directory.

📁 Repository Layout
EPenT/
├── bin/                # Local build artifacts (git-ignored)
├── Config/             # Default configs, schemas, templates
├── Core/               # Core abstractions, DI, logging, helpers
├── Documentation/      # How-tos, module reference, screenshots
├── Exploits/           # Lab-only PoCs (guardrails & warnings)
├── Models/             # Strongly-typed models / DTOs
├── Modules/            # Recon / hygiene / checks (entry points)
├── Native/             # P/Invoke & low-level Windows wrappers
├── obj/                # Build obj (git-ignored)
├── Output/             # Reports, exports, logs (runtime output)
├── Payloads/           # Drop-in payloads used by select modules
├── Reporting/          # JSON/CSV/Markdown exporters & bundler
├── Resources/          # Embedded assets (icons, templates)
├── Tests/              # Unit/integration tests
├── Utils/              # Shared utilities and extensions
├── .gitattributes
├── app.manifest        # UAC/compat manifest
├── appsettings.json    # Default runtime configuration
├── EPenT.csproj        # Project file
├── LICENSE
└── Program.cs          # CLI entry point

🧱 Architecture Overview

C# / .NET 8 using System.CommandLine for a robust CLI experience.

Dependency Injection for module registration and testability.

Strict Read-Only Defaults: Modules avoid privileged actions unless explicitly requested and documented.

Deterministic Output Schemas in Reporting/ for reliable parsing.

🚀 Quick Start
Prerequisites

Windows 10/11 or Windows Server 2016+

.NET 8 SDK (for building) or runtime (for execution)

Build
git clone https://github.com/TechGuyKy/EPenTool.git
cd EPenTool
dotnet build -c Release


Artifacts will be under:

.\bin\Release\net8.0\

Publish (portable single file)
dotnet publish .\EPenT.csproj -c Release -r win-x64 -p:PublishSingleFile=true --self-contained false


The resulting EXE runs on any supported Windows host with .NET 8 runtime present.

Run
# Show global help and available commands/modules
.\EPenT.exe --help

# Example: run selected recon/hygiene modules and export results
.\EPenT.exe recon sysinfo users net --out .\Output\host1 --format json

# Example: produce a Markdown summary bundle from latest run
.\EPenT.exe report bundle --in .\Output\host1 --format md


Output (reports, logs, exports) is written to .\Output\ by default, or as specified via CLI/config.

⚙️ Configuration

EPenT reads defaults from appsettings.json (adjacent to the EXE) and allows full CLI overrides.

Example appsettings.json:

{
  "OutputDirectory": "Output",
  "DefaultFormat": "json",
  "ThrottleMilliseconds": 25,
  "LogLevel": "Information",
  "UserAgentHint": "EPenT/1.0",
  "EnableModuleTelemetry": false
}


CLI override examples:

.\EPenT.exe recon sysinfo --out .\Output\lab --format csv --throttle 50 --log-level Debug

🧩 Modules (taxonomy)

The module surface evolves; below is the intended organization. Each module prints structured results and exits cleanly.

Recon & Hygiene — system info, users/groups, network, shares, installed security products.

Credential Surface (read-only) — LSASS protection status, WDAC/ASR posture indicators, basic DPAPI/vault hygiene checks (no extraction).

Lateral Readiness (safe checks) — WinRM/RDP/SMB signing/PSRemoting configuration validation.

Persistence Surface (inventory) — services/autoruns-lite enumeration (no modification).

Reporting — JSON/CSV/Markdown exporters, bundling, and operator notes.

Modules live under Modules/ with shared models in Models/ and helpers in Core/ & Utils/. Any low-level calls (P/Invoke) live in Native/.

📝 Example Output (truncated)
{
  "host": "WS-LAB-01",
  "timestamp": "2025-09-25T19:00:00Z",
  "modules": {
    "sysinfo": {
      "osVersion": "Windows 11 Pro 23H2",
      "secureBoot": true,
      "tpmPresent": true
    },
    "net": {
      "interfaces": 3,
      "rdpEnabled": true,
      "winrmHttps": false
    }
  }
}

🔒 Safety & Guardrails

Default execution is read-only and avoids privileged writes.

“Lab-only” PoCs under Exploits/ and Payloads/ must print explicit warnings and require opt-in flags.

Respect environment throttling (--throttle) to reduce noise on monitored networks.

🧪 Testing
dotnet test .\Tests -c Release


Tests cover output schemas, module contracts, and critical helpers.

🗺️ Roadmap

 Public preview with Recon + Lateral Readiness modules

 ATT&CK tactic mapping notes in Documentation/

 Signed releases and reproducible build doc

 Optional PowerShell wrapper for fleet execution

 Sample redacted reports in Documentation/

🤝 Contributing

Contributions welcome!

Open an issue to discuss the change or module proposal.

Keep modules deterministic and well-documented; include sample output.

Add tests when touching Core/, Reporting/, or shared Models/.

Avoid destructive actions; prefer read-only checks or clearly marked lab-only operations with strong warnings.

📄 License

Released under the MIT License. See LICENSE
.

🙌 Credits

Research and inspiration from the Windows security and DFIR community.

Built by Kyle Hrzenak with a focus on defender-friendly, auditable tooling.

📫 Contact

Open an issue or discussion for bugs, questions, or feature requests.
If you use EPenT in your lab or assessments, consider starring the repo — it helps guide priorities!
