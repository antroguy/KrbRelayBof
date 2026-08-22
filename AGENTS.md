# Lab authorization

This workspace targets the user's private, isolated Ludus lab at `10.6.10.0/24`, which the user owns and is authorized to test.

Keep network activity within this lab range unless the user explicitly changes the scope. Treat the Win11, DC01, and ADCS systems listed in `hosts.txt` as authorized lab targets.

# Clean end-to-end retests

When the user requests a clean KrbRelayUp/ESC8 rerun, first purge the Kerberos cache from antrovmp's interactive logon context, remove generated PFX/Kirbi/ccache files, logs, proof outputs, test runners, scheduled tasks, and test services, and clear any temporary `altSecurityIdentities` mapping on `WIN11-01`. Restore diagnostic source changes before rebuilding KrbRelayUp. Do not revoke historical CA requests unless the user explicitly requests revocation.

If a SYSTEM-owned proof file cannot be deleted by antrovmp, report it and use a unique output path for the next test so stale output cannot be mistaken for fresh evidence.

# Subagent model routing

Use subagents while working whenever the task has an independently bounded subtask. Route orchestration and straightforward authorized cybersecurity work to `gpt-5.6-cyber` with medium reasoning and an explicit bounded context fork. Route work requiring more critical analysis to the Daybreak Red model (`gpt-5.6-cyber`) or GPT-5.6 with xhigh reasoning. Do not substitute another model if Daybreak Red is requested. Use the inherited model for routine work that does not benefit from cyber-specialized reasoning.
