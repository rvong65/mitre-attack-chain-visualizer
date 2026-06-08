"""
Refined chain detection: GUID-first linking, name+time fallback (60-300s), benign root filtering,
refined technique rules and confidence (base 20% + sequence bonus), UI columns for Plotly/Streamlit.
"""
import bisect
import re
from pathlib import Path
from typing import Any

import pandas as pd

from .config import PROCESSED_DIR
from .chain_detection import load_processed_df, _parse_timestamp
from .timeline_viz_helpers import _technique_to_color

# Time window for name+time fallback (seconds)
_NAME_TIME_WINDOW_MIN = 60
_NAME_TIME_WINDOW_MAX = 300
# Benign root process path patterns (case-insensitive)
_BENIGN_ROOT_PATTERN = re.compile(
    r"svchost\.exe|splunkd\.exe|lsass\.exe|splunk-",
    re.IGNORECASE,
)


def _norm_path(s: Any) -> str:
    if pd.isna(s):
        return ""
    return str(s).strip().lower().replace("\\", "/")


def _path_trailing(name: str) -> str:
    """Return trailing part of path (e.g. 'powershell.exe')."""
    n = _norm_path(name)
    if not n:
        return ""
    return n.split("/")[-1].strip()


def _union_find(n: int, edges: list[tuple[int, int]]) -> list[int]:
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


def _partial_path_match(parent_val: str, process_path_val: str) -> bool:
    """True if parent (e.g. 'C:\\...\\powershell.exe') matches process_path (contains same trailing exe)."""
    trail = _path_trailing(parent_val)
    if not trail:
        return False
    pp = _norm_path(process_path_val)
    return trail in pp or pp.endswith(trail) or pp == _norm_path(parent_val)


def build_chains_refined(
    df: pd.DataFrame,
    name_time_sec: int = 120,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Build chains: GUID-first (if ProcessGuid/ParentProcessGuid exist), then name+time fallback
    (60-300s, partial path match). Union-find; add chain_id and is_multi_event_chain.
    Mark chain_benign_root_only for chains whose root is benign and have no suspicious indicators.
    """
    df = df.copy()
    n = len(df)
    if n == 0:
        df["chain_id"] = []
        df["is_multi_event_chain"] = []
        return df, pd.DataFrame()

    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    pp = df["process_path"].map(_norm_path)
    parent = df["parent_process"].fillna("")

    edges: list[tuple[int, int]] = []
    has_guid = "ProcessGuid" in df.columns and "ParentProcessGuid" in df.columns
    guid_ok = has_guid and df["ProcessGuid"].notna().any() and df["ParentProcessGuid"].notna().any()

    if has_guid and not guid_ok:
        print("  [Warning] Missing ProcessGuid/ParentProcessGuid; using name+time fallback only.")

    if guid_ok:
        pg = df["ProcessGuid"].fillna("").astype(str).str.strip()
        ppg = df["ParentProcessGuid"].fillna("").astype(str).str.strip()
        guid_to_indices: dict[str, list[int]] = {}
        for i in range(n):
            g = pg.iloc[i]
            if g:
                guid_to_indices.setdefault(g, []).append(i)
        for i in range(n):
            pguid = ppg.iloc[i]
            if not pguid:
                continue
            for j in guid_to_indices.get(pguid, []):
                if i != j:
                    edges.append((i, j))

    # Name + time fallback: window name_time_sec (within 60-300)
    window_sec = max(_NAME_TIME_WINDOW_MIN, min(_NAME_TIME_WINDOW_MAX, name_time_sec))
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

    # Name+time: link each child to at most one parent (closest in time before child, or within window)
    for i in range(n):
        parent_val = parent.iloc[i]
        if pd.isna(parent_val) or str(parent_val).strip() == "":
            continue
        ti = ts.iloc[i]
        if pd.isna(ti):
            continue
        trail = _path_trailing(parent_val)
        cands: list[tuple[pd.Timestamp, int]] = []
        if trail:
            for path_key, lst in path_to_times.items():
                if trail in path_key or path_key.endswith(trail) or _norm_path(parent_val) == path_key:
                    cands.extend(lst)
        if not cands:
            continue
        cands = list(set(cands))
        cands.sort(key=lambda x: x[0])
        times_only = [c[0] for c in cands]
        lo = bisect.bisect_left(times_only, ti - pd.Timedelta(seconds=window_sec))
        hi = bisect.bisect_right(times_only, ti + pd.Timedelta(seconds=window_sec))
        best_j: int | None = None
        best_delta: float = 1e9
        for idx in range(lo, hi):
            tj, j = cands[idx]
            if i == j:
                continue
            if not _partial_path_match(parent_val, df["process_path"].iloc[j]):
                continue
            delta = abs((ti - tj).total_seconds())
            if delta <= window_sec and delta < best_delta:
                best_delta = delta
                best_j = j
        if best_j is not None:
            edges.append((i, best_j))

    representatives = _union_find(n, edges)
    uniq = sorted(set(representatives))
    rep_to_cid = {r: k for k, r in enumerate(uniq)}
    df["chain_id"] = [rep_to_cid[r] for r in representatives]
    chain_to_indices: dict[int, list[int]] = {}
    for i, cid in enumerate(df["chain_id"]):
        chain_to_indices.setdefault(cid, []).append(i)
    df["is_multi_event_chain"] = df["chain_id"].map(lambda c: len(chain_to_indices[c]) > 1)

    # Build chains_df and compute chain_benign_root_only per chain
    rows = []
    for cid in sorted(chain_to_indices.keys()):
        indices = chain_to_indices[cid]
        sub = df.iloc[indices]
        t_min, t_max = sub["timestamp"].min(), sub["timestamp"].max()
        duration = (t_max - t_min).total_seconds() if pd.notna(t_min) and pd.notna(t_max) else 0
        benign = _is_benign_root_chain(sub, df, indices)
        rows.append({
            "chain_id": cid,
            "event_indices": indices,
            "num_events": len(indices),
            "start_time": t_min,
            "end_time": t_max,
            "duration_seconds": duration,
            "chain_benign_root_only": benign,
            "is_multi_event_chain": len(indices) > 1,
        })
    chains_df = pd.DataFrame(rows)
    return df, chains_df


def _is_benign_root_chain(chain_events: pd.DataFrame, full_df: pd.DataFrame, indices: list[int]) -> bool:
    """True if chain root is benign (svchost/splunkd/lsass/splunk-*) and chain has no suspicious indicators."""
    # Root = event(s) whose parent_process is not any other event's process_path in this chain
    pp_in_chain = set(str(full_df["process_path"].iloc[i]).strip().lower() for i in indices)
    roots = []
    for i in indices:
        par = full_df["parent_process"].iloc[i]
        par_norm = _norm_path(par) if pd.notna(par) else ""
        if not par_norm or par_norm not in pp_in_chain:
            roots.append(full_df["process_path"].iloc[i])
    if not roots:
        return False
    root_path = str(roots[0]).strip().lower()
    if not _BENIGN_ROOT_PATTERN.search(root_path):
        return False
    # No T1059.001, T1547.001, T1003.* indicators in chain
    sub = chain_events
    def has(col: str) -> bool:
        return col in sub.columns and sub[col].fillna(0).astype(int).sum() > 0
    if has("has_powershell_process") or has("has_base64") or has("has_enc_flags"):
        return False
    if has("has_run_registry") or has("has_reg_exe") or has("has_set_itemproperty"):
        return False
    if has("has_lsass_mention") or has("has_procdump_minidump") or has("has_comsvcs_rundll32"):
        return False
    cmd = sub.get("cmdline", pd.Series(dtype=str)).fillna("").astype(str)
    if cmd.str.contains(r"-enc\b|-EncodedCommand|Invoke-Expression", case=False, regex=True).any():
        return False
    if cmd.str.contains(r"reg\s+add|Set-ItemProperty.*Run|comsvcs\.dll|MiniDump|lsass", case=False, regex=True).any():
        return False
    return True


def detect_chain_techniques_refined(chain_events: pd.DataFrame) -> tuple[list[str], float, str, set[str]]:
    """
    Refined rules: T1059.001 (exec), T1547.001 (persist), T1003.* (cred).
    Base 20% + indicator bonuses (+20 strong, +10 weak) + length bonus + sequence bonus +20%.
    Returns (predicted_techniques, confidence 0-100, explanation, ground_truth_techniques).
    """
    if chain_events.empty:
        return [], 0.0, "No events.", set()

    gt = set(chain_events["technique_id"].dropna().astype(str).unique()) if "technique_id" in chain_events.columns else set()
    n_events = len(chain_events)
    chain_events = chain_events.sort_values("timestamp").reset_index(drop=True)

    def has(col: str) -> bool:
        return col in chain_events.columns and chain_events[col].fillna(0).astype(int).sum() > 0

    def any_cmdline(pattern: str) -> bool:
        c = chain_events.get("cmdline", pd.Series(dtype=str)).fillna("").astype(str)
        return c.str.contains(pattern, case=False, regex=True).any()

    def any_reg(pattern: str) -> bool:
        r = chain_events.get("registry_key", pd.Series(dtype=str)).fillna("").astype(str)
        return r.str.contains(pattern, case=False, regex=True).any()

    # T1059.001
    exec_strong = has("has_powershell_process") or has("has_base64") or has("has_enc_flags")
    exec_weak = any_cmdline(r"-enc\b|-EncodedCommand|Invoke-Expression") or (
        any(c for c in chain_events.columns if c.startswith("event_") and "PowerShell" in c)
        and chain_events[[c for c in chain_events.columns if c.startswith("event_") and "PowerShell" in c]].fillna(0).astype(int).sum().sum() > 0
    )
    execution = exec_strong or exec_weak

    # T1547.001
    persist_strong = has("has_run_registry")
    persist_weak = any_reg(r"Run|Startup") or any_cmdline(r"reg\s+add\s+.*Run|Set-ItemProperty.*Run")
    persistence = persist_strong or persist_weak or (has("has_reg_exe") and has("has_set_itemproperty"))

    # T1003.*
    cred_strong = has("has_lsass_mention") or has("has_procdump_minidump")
    cred_weak = has("has_comsvcs_rundll32") or any_cmdline(r"comsvcs\.dll|MiniDump|lsass\.exe")
    cred = cred_strong or cred_weak
    cred_tech = "T1003.001" if has("has_lsass_mention") else ("T1003.003" if cred else None)

    predicted: list[str] = []
    if execution:
        predicted.append("T1059.001")
    if persistence:
        predicted.append("T1547.001")
    if cred_tech:
        predicted.append(cred_tech)

    # Confidence: base 20% + strong +20 each, weak +10 + length bonus (+10 per event >1, cap 50) + sequence +20%
    conf = 20.0
    if exec_strong:
        conf += 20
    elif exec_weak:
        conf += 10
    if persist_strong:
        conf += 20
    elif persistence:
        conf += 10
    if cred_strong:
        conf += 20
    elif cred_weak:
        conf += 10
    length_bonus = min(50, (n_events - 1) * 10) if n_events > 1 else 0
    conf += length_bonus
    if execution and persistence:
        conf += 20  # sequence bonus Execution -> Persistence
    conf = min(100.0, conf)

    # Explanation: key events + indicators (ASCII)
    parts = []
    first = chain_events.iloc[0]
    last = chain_events.iloc[-1]
    p1 = str(first.get("process_path", ""))[:60]
    p2 = str(last.get("process_path", ""))[:60]
    parts.append(f"Chain: {p1}")
    if p2 != p1:
        parts.append(f" -> {p2}")
    if execution:
        parts.append("; powershell/encoded cmd")
    if persistence:
        parts.append("; reg add to Run key")
    if cred:
        parts.append("; credential dump indicators")
    parts.append(". Likely " + ", ".join(predicted) if predicted else ". No technique matched")
    if execution and persistence:
        parts.append(" (Execution -> Persistence)")
    parts.append(f". Confidence {conf:.0f}%.")
    explanation = "".join(parts)

    return predicted, conf, explanation, gt


def run_chain_detection_refined(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Load -> build_chains_refined -> detect per chain -> add UI columns (chain_techniques, technique_color, hover_text)
    -> summarize -> save events_with_chains_refined.csv and chains_summary_refined.csv -> print stats, 8-10 samples, warnings.
    """
    df = load_processed_df(csv_path)
    df, chains_df = build_chains_refined(df)

    chain_id_to_pred: dict[int, tuple[list[str], float, str]] = {}
    for _, row in chains_df.iterrows():
        cid = row["chain_id"]
        indices = row["event_indices"]
        sub = df.iloc[indices]
        pred, conf, expl, _ = detect_chain_techniques_refined(sub)
        chain_id_to_pred[cid] = (pred, conf, expl)

    pred_tech_list = []
    chain_conf_list = []
    chain_expl_list = []
    for cid in df["chain_id"]:
        p, c, e = chain_id_to_pred.get(cid, ([], 0.0, ""))
        pred_tech_list.append(";".join(p) if p else "")
        chain_conf_list.append(c)
        chain_expl_list.append(e)
    df["predicted_chain_techniques"] = pred_tech_list
    df["chain_techniques"] = pred_tech_list
    df["chain_confidence"] = chain_conf_list
    df["chain_explanation"] = chain_expl_list
    df["technique_color"] = df["chain_techniques"].map(_technique_to_color)

    # Hover text for Plotly
    def _hover(row: pd.Series) -> str:
        pp = str(row.get("process_path", ""))[:50]
        cmd = str(row.get("cmdline", ""))[:80].replace("\n", " ")
        expl = str(row.get("chain_explanation", ""))[:100]
        return f"{pp} | {cmd} | {expl}"
    df["hover_text"] = df.apply(_hover, axis=1)

    # Summary with chain_benign_root_only and is_multi_event_chain
    summary = df.groupby("chain_id").agg(
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
        techniques=("chain_techniques", "first"),
        chain_confidence=("chain_confidence", "first"),
        chain_explanation=("chain_explanation", "first"),
    ).reset_index()
    n_events = df.groupby("chain_id").size().reset_index(name="num_events")
    summary = summary.merge(n_events, on="chain_id")
    benign_map = chains_df.set_index("chain_id")["chain_benign_root_only"]
    summary["chain_benign_root_only"] = summary["chain_id"].map(benign_map).fillna(False)
    summary["is_multi_event_chain"] = summary["chain_id"].map(
        lambda c: chains_df.loc[chains_df["chain_id"] == c, "is_multi_event_chain"].iloc[0] if (chains_df["chain_id"] == c).any() else False
    )

    # Save
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_events = PROCESSED_DIR / "events_with_chains_refined.csv"
    out_summary = PROCESSED_DIR / "chains_summary_refined.csv"
    df.to_csv(out_events, index=False)
    summary.to_csv(out_summary, index=False)
    print(f"Saved {out_events} and {out_summary}")

    # Stats
    n_chains = len(chains_df)
    orphans = (chains_df["num_events"] == 1).sum()
    pct_orphans = 100.0 * orphans / n_chains if n_chains else 0
    multi = chains_df[chains_df["num_events"] > 1]
    events_in_multi = multi["num_events"].sum()
    pct_events_multi = 100.0 * events_in_multi / len(df) if len(df) else 0
    avg_multi_len = multi["num_events"].mean() if len(multi) else 0
    benign_count = chains_df["chain_benign_root_only"].sum()

    print("\n--- Chain stats (refined) ---")
    print(f"  Number of chains: {n_chains}")
    print(f"  Orphans (single-event): {orphans} ({pct_orphans:.1f}%)")
    print(f"  Events in multi-event chains: {events_in_multi} ({pct_events_multi:.1f}%)")
    print(f"  Avg chain length (multi-event only): {avg_multi_len:.1f}")
    print(f"  Benign-root-only chains: {benign_count}")
    if benign_count > 0 and benign_count / max(1, n_chains) > 0.3:
        print(f"  [Warning] High fraction of benign-root-only chains ({100*benign_count/n_chains:.0f}%).")

    # Sample 8-10 chains: prioritize multi-event, multi-technique or high conf; exclude benign_root_only
    candidate = chains_df[~chains_df["chain_benign_root_only"] & (chains_df["num_events"] > 1)].copy()
    if len(candidate) == 0:
        candidate = chains_df[~chains_df["chain_benign_root_only"]].copy()
    candidate["_conf"] = candidate["chain_id"].map(lambda c: chain_id_to_pred.get(c, ([], 0.0, ""))[1])
    candidate["_multi_tech"] = candidate["chain_id"].map(
        lambda c: len(chain_id_to_pred.get(c, ([], 0.0, ""))[0]) >= 2
    )
    candidate = candidate.sort_values(["_multi_tech", "_conf"], ascending=[False, False])
    sample_df = candidate.head(10)

    print("\n--- Sample chains (multi-event, multi-technique or high conf) ---")
    for _, row in sample_df.iterrows():
        cid = row["chain_id"]
        indices = row["event_indices"]
        pred, conf, expl = chain_id_to_pred[cid]
        expl_safe = expl.encode("ascii", "replace").decode("ascii")
        print(f"\n  chain_id={cid}  time=[{row['start_time']} .. {row['end_time']}]  techniques={pred}  confidence={conf:.0f}%")
        print(f"  explanation: {expl_safe[:220]}...")
        sub = df.iloc[indices].head(8)
        for _, ev in sub.iterrows():
            pp = str(ev.get("process_path", ""))[:80]
            cmd = str(ev.get("cmdline", ""))[:60] + ("..." if len(str(ev.get("cmdline", ""))) > 60 else "")
            safe = lambda s: s.encode("ascii", "replace").decode("ascii")
            print(f"    - {safe(pp)}  |  {safe(cmd)}")

    return df


if __name__ == "__main__":
    run_chain_detection_refined()
