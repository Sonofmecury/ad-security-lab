# Active Directory security lab

Review administrative group membership, password lifecycle for service accounts and broad write permissions on shares. The comparison report carries evidence and only marks a finding closed when a failed baseline check passes on the later snapshot.

```sh
python audit.py fixtures/baseline.json fixtures/hardened.json
python -m unittest discover -v
```

Python 3.11+, no Python dependencies. The fixtures are fictional and the replay runs without Windows VMs.

## Lab runbook

Use a host-only virtual network with a Windows Server domain controller, DNS on the controller and one domain-joined Windows client. Keep a separate test share with fictional files. Take a snapshot after the domain join, record VM/OS versions and use test identities. Set up a known administrator, a normal file reader and a file editor before scoring changes.

1. On the controller, with the ActiveDirectory module available, run `Collect-Directory.ps1` and pass the domain admin group identity, approved administrator names and ordinary service accounts in scope. On the share host, use the script’s share-only parameter set. Run elevated only if your host requires it.
2. Merge the directory and share JSON objects under one local baseline file. Both partial snapshots are valid inputs. Checks that lack a collection report `unknown`.
3. Review group membership with the designated administrator and remove unapproved membership through your normal change procedure. Review legacy service identities and migrate eligible workloads to a gMSA with a rollback account and service validation. Narrow share writes to a designated group and check the separate NTFS ACL.
4. Repeat the collection. Recheck an approved administrator login, application service startup, expected file write and expected read access as normal lab users. Record the time and evidence in the case report. Use VM snapshots to recover the disposable lab if needed.
5. Compare snapshots and retain redacted findings. Review Windows Security and Sysmon logs around the test window and replay their redacted events through your SOC lab if adapting its schema.

## Limits

The three checks inspect effective group membership as reported by AD, account attributes for explicitly named identities and broad explicit share allows. They do not calculate every effective permission across NTFS, inheritance, deny ACEs and domain trusts. A passing fixture validates the model. A real lab report needs a collected baseline, remediation snapshot and recorded authorised workflows.
