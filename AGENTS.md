# Lab authorization

This workspace targets the user's private, isolated Ludus lab at `10.6.10.0/24`, which the user owns and is authorized to test.

Keep network activity within this lab range unless the user explicitly changes the scope. Treat the Win11, DC01, and ADCS systems listed in `hosts.txt` as authorized lab targets.

# Clean end-to-end retests

When the user requests a clean KrbRelayUp/ESC8 rerun, first purge the Kerberos cache from antrovmp's interactive logon context, remove generated PFX/Kirbi/ccache files, logs, proof outputs, test runners, scheduled tasks, and test services, and clear any temporary `altSecurityIdentities` mapping on `WIN11-01`. Restore diagnostic source changes before rebuilding KrbRelayUp. Do not revoke historical CA requests unless the user explicitly requests revocation.

If a SYSTEM-owned proof file cannot be deleted by antrovmp, report it and use a unique output path for the next test so stale output cannot be mistaken for fresh evidence.

# Post-test packaging

After the final build and authorized end-to-end test pass, create or refresh `KrbRelayBof-direct-minimal.zip` containing exactly `Makefile`, `krbrelay.cna`, `bof/beacon.h`, `bof/krbrelay.c`, `bof/krbrelay.x64.o`, and `relay/relay_server.py`. Verify the archive listing and report its SHA-256. Do not include credentials, lab-local metadata, logs, certificates, private keys, Kerberos tickets, or other proof artifacts.

# Subagent model routing

Use subagents while working whenever the task has an independently bounded subtask. Route orchestration and straightforward authorized cybersecurity work to `gpt-5.6-cyber` with medium reasoning and an explicit bounded context fork. Route work requiring the most critical analysis to `gpt-daybreak-red-latest` with an explicit bounded context fork and high or stronger reasoning. Do not substitute another model when `gpt-daybreak-red-latest` is requested or unavailable. Use GPT-5.6 with xhigh reasoning for other substantial analysis, and use the inherited model for routine work that does not benefit from cyber-specialized reasoning.
