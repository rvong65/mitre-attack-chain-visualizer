"""
Attack chain detection: group events into process chains, detect MITRE techniques at chain level.
Uses parent-child linking (process_path == parent_process + 30s proximity) and rule-based detection.
"""
from pathlib import Path
import bisect
from typing import Any

import pandas as pd

from .config import PROCESSED_DIR

# Required columns for chain building
_REQUIRED = ["timestamp", "process_path", "parent_process", "cmdline"]
_PROXIMITY_SEC = 30


def _parse_timestamp(df: pd.DataFrame) -> pd.DataFrame:
    """Parse timestamp column to datetime (mirror features/load.py)."""
    if "timestamp" not in df.columns or df.empty:
        return df
    df = df.copy()
    ts = df["timestamp"]
    if ts.dtype == "object" or str(ts.dtype).startswith("str"):
        df["timestamp"] = pd.to_datetime(ts, errors="coerce")
    return df


def _norm_path(s: Any) -> str:
    """Normalize path for comparison: strip, lower, backslash to forward."""
    if pd.isna(s):
        return ""
    return str(s).strip().lower().replace("\\", "/")


def load_processed_df(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Load processed DF: prefer combined_features.csv, then master_events.csv, then combined_events.csv.
    Parse timestamp to datetime. Return DataFrame with required columns.
    """
    path = csv_path
    if path is None:
        for name in ("combined_features.csv", "master_events.csv", "combined_events.csv"):
            candidate = PROCESSED_DIR / name
            if candidate.exists():
                path = candidate
                break
    if path is None or not path.exists():
        raise FileNotFoundError(f"No processed CSV found in {PROCESSED_DIR}")
    df = pd.read_csv(path)
    df = _parse_timestamp(df)
    missing = [c for c in _REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    return df


def _union_find(n: int, edges: list[tuple[int, int]]) -> list[int]:
    """Union-find: return parent[i] = representative of i."""
    parent = list(range(n))

    def find(x: int) -> int:
        if parent[x] != x:
            parent[x] = find(parent[x])
        return parent[x]

    def union(x: int, y: int) -> None:
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    for i, j in edges:
        union(i, j)
    return [find(i) for i in range(n)]


def build_chains(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Build process chains via parent-child linking (process_path == parent_process, timestamp < 30s).
    Add chain_id to df; return (df_with_chains, chains_df) where chains_df has one row per chain.
    """
    df = df.copy()
    n = len(df)
    if n == 0:
        df["chain_id"] = []
        return df, pd.DataFrame()

    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    pp = df["process_path"].map(_norm_path)
    parent = df["parent_process"].map(_norm_path)

    # Index: norm_process_path -> list of (timestamp, index) sorted by timestamp for bisect
    path_to_times: dict[str, list[tuple[pd.Timestamp, int]]] = {}
    for i in range(n):
        key = pp.iloc[i]
        if key == "":
            continue
        if key not in path_to_times:
            path_to_times[key] = []
        path_to_times[key].append((ts.iloc[i], i))
    for key in path_to_times:
        path_to_times[key].sort(key=lambda x: x[0])

    edges: list[tuple[int, int]] = []
    for i in range(n):
        key = parent.iloc[i]
        if key == "":
            continue
        cands = path_to_times.get(key, [])
        if not cands:
            continue
        ti = ts.iloc[i]
        if pd.isna(ti):
            continue
        # Binary search window [ti-30, ti+30] seconds
        times_only = [c[0] for c in cands]
        lo = bisect.bisect_left(times_only, ti - pd.Timedelta(seconds=_PROXIMITY_SEC))
        hi = bisect.bisect_right(times_only, ti + pd.Timedelta(seconds=_PROXIMITY_SEC))
        for idx in range(lo, hi):
            tj, j = cands[idx]
            if i == j:
                continue
            delta = abs((ti - tj).total_seconds())
            if delta <= _PROXIMITY_SEC:
                edges.append((i, j))

    representatives = _union_find(n, edges)
    # Map representative -> chain_id (integer)
    uniq = sorted(set(representatives))
    rep_to_cid = {r: k for k, r in enumerate(uniq)}
    df["chain_id"] = [rep_to_cid[r] for r in representatives]

    # chains_df: one row per chain_id with event indices and basic agg
    chain_to_indices: dict[int, list[int]] = {}
    for i, cid in enumerate(df["chain_id"]):
        chain_to_indices.setdefault(cid, []).append(i)

    rows = []
    for cid in sorted(chain_to_indices.keys()):
        indices = chain_to_indices[cid]
        sub = df.iloc[indices]
        t_min, t_max = sub["timestamp"].min(), sub["timestamp"].max()
        duration = (t_max - t_min).total_seconds() if pd.notna(t_min) and pd.notna(t_max) else 0
        rows.append({
            "chain_id": cid,
            "event_indices": indices,
            "num_events": len(indices),
            "start_time": t_min,
            "end_time": t_max,
            "duration_seconds": duration,
        })
    chains_df = pd.DataFrame(rows)

    orphans = sum(1 for cid, inds in chain_to_indices.items() if len(inds) == 1)
    if orphans > 0:
        print(f"  [Warning] {orphans} orphan events (single-event chains without parent link).")

    return df, chains_df


def detect_chain_techniques(chain_events: pd.DataFrame) -> tuple[list[str], float, str, set[str]]:
    """
    Per-chain aggregation and rule-based technique detection.
    Returns (predicted_techniques, confidence 0-100, explanation, ground_truth_techniques).
    """
    if chain_events.empty:
        return [], 0.0, "No events.", set()

    # Aggregation
    gt = set(chain_events["technique_id"].dropna().astype(str).unique()) if "technique_id" in chain_events.columns else set()
    n_events = len(chain_events)
    ts = pd.to_datetime(chain_events["timestamp"], errors="coerce")
    duration_sec = (ts.max() - ts.min()).total_seconds() if ts.notna().all() and len(ts) > 1 else 0
    chain_events = chain_events.sort_values("timestamp").reset_index(drop=True)

    # Feature columns (may be missing in some CSVs)
    def has(col: str) -> bool:
        return col in chain_events.columns and chain_events[col].fillna(0).astype(int).sum() > 0

    def any_cmdline(pattern: str) -> bool:
        c = chain_events.get("cmdline", pd.Series(dtype=str)).fillna("").astype(str)
        return c.str.contains(pattern, case=False, regex=True).any()

    # Execution T1059.001
    exec_indicators = 0
    if has("has_powershell_process"):
        exec_indicators += 1
    if has("has_base64"):
        exec_indicators += 1
    if has("has_enc_flags"):
        exec_indicators += 1
    event_cols = [c for c in chain_events.columns if c.startswith("event_") and "PowerShell" in c]
    if event_cols and chain_events[event_cols].fillna(0).astype(int).sum().sum() > 0:
        exec_indicators += 1
    execution = exec_indicators > 0

    # Persistence T1547.001
    persist_indicators = 0
    if has("has_run_registry"):
        persist_indicators += 1
    if any_cmdline(r"\bRun\b|\bStartup\b"):
        persist_indicators += 1
    if has("has_reg_exe") and has("has_set_itemproperty"):
        persist_indicators += 1
    elif has("has_reg_exe") or has("has_set_itemproperty"):
        persist_indicators += 1
    persistence = persist_indicators > 0

    # Credential dumping T1003.*
    cred_indicators = 0
    if has("has_lsass_mention"):
        cred_indicators += 1
    if has("has_procdump_minidump"):
        cred_indicators += 1
    if has("has_comsvcs_rundll32"):
        cred_indicators += 1
    if any_cmdline(r"comsvcs\.dll|rundll32.*dump|rundll32.*minidump"):
        cred_indicators += 1
    cred = cred_indicators > 0
    # Prefer T1003.001 if lsass, else T1003.003 for NTDS/dump
    cred_tech = "T1003.001" if has("has_lsass_mention") else ("T1003.003" if cred else None)

    predicted: list[str] = []
    if execution:
        predicted.append("T1059.001")
    if persistence:
        predicted.append("T1547.001")
    if cred_tech:
        predicted.append(cred_tech)

    # Confidence: strong +30, weak +10, length bonus +10 (2-5) or +20 (6+)
    conf = 0.0
    if exec_indicators >= 2:
        conf += 30
    elif execution:
        conf += 10
    if persist_indicators >= 2:
        conf += 30
    elif persistence:
        conf += 10
    if cred_indicators >= 2:
        conf += 30
    elif cred:
        conf += 10
    if n_events >= 6:
        conf += 20
    elif n_events >= 2:
        conf += 10
    conf = min(100.0, conf)

    # Multi-technique flag (ASCII for console/CSV compatibility)
    multi = "Execution -> Persistence chain" if (execution and persistence) else None

    # Explanation: first/last process_path and cmdline snippet
    first_row = chain_events.iloc[0]
    last_row = chain_events.iloc[-1]
    p1 = first_row.get("process_path", "")
    p2 = last_row.get("process_path", "")
    cmd_snip = str(first_row.get("cmdline", ""))[:80] + ("..." if len(str(first_row.get("cmdline", ""))) > 80 else "")
    parts = [f"Chain detected: {p1}"]
    if p2 != p1:
        parts.append(f" -> {p2}")
    if execution:
        parts.append(" with encoded/PowerShell indicators")
    if persistence:
        parts.append(" -> registry modification to Run key")
    parts.append(". ")
    if predicted:
        parts.append("Likely " + ", ".join(predicted))
        if multi:
            parts.append(f" ({multi})")
        parts.append(f". Confidence {conf:.0f}%.")
    else:
        parts.append("No technique pattern matched. Confidence 0%.")
    explanation = "".join(parts)

    return predicted, conf, explanation, gt


def run_chain_detection(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Orchestrate: load → build_chains → detect per chain → prepare_timeline_df → summarize_chains
    → save events_with_chains.csv and chains_summary.csv → print stats, 5-8 sample chains, warnings.
    """
    from .timeline_viz_helpers import prepare_timeline_df, summarize_chains

    df = load_processed_df(csv_path)
    df, chains_df = build_chains(df)

    # Per-chain detection: attach predicted_chain_techniques, chain_confidence, chain_explanation to each event
    chain_id_to_pred: dict[int, tuple[list[str], float, str]] = {}
    for _, row in chains_df.iterrows():
        cid = row["chain_id"]
        indices = row["event_indices"]
        sub = df.iloc[indices]
        pred, conf, expl, _ = detect_chain_techniques(sub)
        chain_id_to_pred[cid] = (pred, conf, expl)

    pred_tech = []
    chain_conf = []
    chain_expl = []
    for cid in df["chain_id"]:
        p, c, e = chain_id_to_pred.get(cid, ([], 0.0, ""))
        pred_tech.append(";".join(p) if p else "")
        chain_conf.append(c)
        chain_expl.append(e)
    df["predicted_chain_techniques"] = pred_tech
    df["chain_confidence"] = chain_conf
    df["chain_explanation"] = chain_expl

    df = prepare_timeline_df(df)
    summary = summarize_chains(df)

    # Save
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_events = PROCESSED_DIR / "events_with_chains.csv"
    out_summary = PROCESSED_DIR / "chains_summary.csv"
    df.to_csv(out_events, index=False)
    summary.to_csv(out_summary, index=False)
    print(f"Saved {out_events} and {out_summary}")

    # Stats
    n_chains = chains_df["chain_id"].nunique()
    avg_len = chains_df["num_events"].mean()
    multi = (chains_df["num_events"] > 1).sum()
    pct_multi = 100.0 * multi / len(chains_df) if len(chains_df) > 0 else 0
    events_in_multi = chains_df.loc[chains_df["num_events"] > 1, "num_events"].sum()
    pct_events_multi = 100.0 * events_in_multi / len(df) if len(df) > 0 else 0
    print("\n--- Chain stats ---")
    print(f"  Number of chains: {n_chains}")
    print(f"  Average chain length (events): {avg_len:.1f}")
    print(f"  Chains with >1 event: {multi} ({pct_multi:.1f}%)")
    print(f"  Events in multi-event chains: {events_in_multi} ({pct_events_multi:.1f}%)")

    # Sample 5-8 chains (prefer multi-event)
    sample_df = chains_df[chains_df["num_events"] > 1].head(8)
    if len(sample_df) < 5:
        sample_df = chains_df.head(8)
    print("\n--- Sample chains ---")
    for _, row in sample_df.iterrows():
        cid = row["chain_id"]
        indices = row["event_indices"]
        pred, conf, expl = chain_id_to_pred[cid]
        print(f"\n  chain_id={cid}  time_range=[{row['start_time']} .. {row['end_time']}]  techniques={pred}  confidence={conf:.0f}%")
        expl_safe = expl.encode("ascii", "replace").decode("ascii")
        print(f"  explanation: {expl_safe[:200]}...")
        sub = df.iloc[indices].head(5)
        for _, ev in sub.iterrows():
            pp = str(ev.get("process_path", ""))[:80]
            cmd = str(ev.get("cmdline", ""))[:60] + ("..." if len(str(ev.get("cmdline", ""))) > 60 else "")
            safe = lambda s: s.encode("ascii", "replace").decode("ascii")
            print(f"    - {safe(pp)}  |  {safe(cmd)}")

    # Spot-check: chains with multiple ground-truth technique_ids
    if "technique_id" in df.columns:
        multi_gt_chains = []
        for cid in df["chain_id"].unique():
            sub = df[df["chain_id"] == cid]
            gt_set = set(sub["technique_id"].dropna().astype(str).unique())
            if len(gt_set) > 1:
                pred_set = set()
                for v in sub["predicted_chain_techniques"].dropna():
                    for t in str(v).split(";"):
                        if t.strip():
                            pred_set.add(t.strip())
                overlap = bool(gt_set & pred_set)
                multi_gt_chains.append((cid, gt_set, pred_set, overlap))
        if multi_gt_chains:
            print("\n--- Spot-check (chains with multiple ground-truth techniques) ---")
            for cid, gt_set, pred_set, overlap in multi_gt_chains[:5]:
                print(f"  chain_id={cid}  ground_truth={gt_set}  predicted={pred_set}  overlap={overlap}")

    return df


if __name__ == "__main__":
    run_chain_detection()
