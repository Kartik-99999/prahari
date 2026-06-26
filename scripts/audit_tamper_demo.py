#!/usr/bin/env python3
"""Prahari audit-ledger tamper demo (defense-in-depth: prevention + detection).

1. verify_chain() on the intact ledger           -> OK
2. simulate a privileged-insider bypass of the append-only trigger:
   ALTER TABLE ... DISABLE TRIGGER; UPDATE one entry (change a gated
   disable_user action's target); re-ENABLE TRIGGER
3. verify_chain()                                 -> BROKEN at seq N + what changed

The trigger (prevention) stops ordinary tampering; the hash chain (detection)
catches tampering even when a superuser disables the trigger.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from services.soar import audit  # noqa: E402

TRIGGER = "audit_ledger_append_only"


def main() -> None:
    conn = audit.get_conn()
    try:
        print("=" * 64)
        print("  PRAHARI AUDIT-LEDGER TAMPER DEMO")
        print("=" * 64)

        # (a) intact chain
        res = audit.verify_chain(conn)
        print(
            f"\n[1] verify_chain on intact ledger: "
            f"{'OK' if res['ok'] else 'BROKEN'}  ({res.get('entries')} entries, "
            f"head {res.get('head_hash')})"
        )
        if not res["ok"]:
            print("    Ledger already broken — run `make respond` to rebuild it first.")
            sys.exit(1)

        # locate a gated disable_user entry to tamper with
        with conn.cursor() as cur:
            cur.execute(
                "SELECT seq, target FROM audit_ledger "
                "WHERE action = 'disable_user' ORDER BY seq LIMIT 1"
            )
            row = cur.fetchone()
        if not row:
            print("    No disable_user entry found; run `make respond` first.")
            sys.exit(1)
        seq, old_target = row
        new_target = (
            "intern.account"  # attacker hides that the domain admin was disabled
        )

        # (b) privileged-insider bypass: disable trigger, mutate, re-enable
        print(f"\n[2] Simulating privileged-insider tamper on seq {seq}:")
        print(f"    ALTER TABLE audit_ledger DISABLE TRIGGER {TRIGGER}")
        print(f"    UPDATE seq {seq}: target '{old_target}' -> '{new_target}'")
        print(f"    ALTER TABLE audit_ledger ENABLE TRIGGER {TRIGGER}")
        with conn.cursor() as cur:
            cur.execute(f"ALTER TABLE audit_ledger DISABLE TRIGGER {TRIGGER}")
            cur.execute(
                "UPDATE audit_ledger SET target = %s WHERE seq = %s", (new_target, seq)
            )
            cur.execute(f"ALTER TABLE audit_ledger ENABLE TRIGGER {TRIGGER}")
        conn.commit()

        # (c) detection
        res2 = audit.verify_chain(conn)
        print("\n[3] verify_chain after tamper: " f"{'OK' if res2['ok'] else 'BROKEN'}")
        if not res2["ok"]:
            print(f"    >>> BROKEN at seq {res2['broken_seq']}: {res2['reason']}")
            print(
                f"    >>> stored entry_hash {res2.get('stored_hash')} != "
                f"recomputed {res2.get('recomputed_hash')}"
            )
            print(
                f"    >>> the altered field: target was '{old_target}', "
                f"now '{new_target}' — the hash no longer matches the row contents."
            )
        else:
            print("    UNEXPECTED: tamper not detected!")
            sys.exit(2)

        print(
            "\n  Defense-in-depth shown: the append-only trigger blocks ordinary "
            "UPDATE/DELETE;\n  even a superuser who disables it cannot evade the "
            "hash chain, which pins\n  every row to its predecessor. Rebuild the "
            "canonical ledger with `make respond`."
        )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
