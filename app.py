"""
MITRE ATT&CK Attack Chain Visualizer — Streamlit app.
"""
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Ensure project root on path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import PROCESSED_DIR
from src.chain_polish import (
    TACTIC_COLORS,
    load_refined_data,
    apply_polish_filters,
    add_tactic_mapping,
    build_chains_summary_polished,
)

st.set_page_config(page_title="ATT&CK Chain Visualizer", layout="wide")

# Dark cyber theme CSS — full dark mode: bg #0e1117, panels #1e1e1e, text #e0e0e0/#ffffff, accents #00ff9f
st.markdown(
    """
    <style>
    .stApp, [data-testid="stAppViewContainer"], .main .block-container { background-color: #0e1117 !important; }
    header[data-testid="stHeader"], .st-emotion-cache-1r6slb0, [data-testid="stHeader"] { background-color: #0e1117 !important; }
    .stApp { color: #e0e0e0; }
    body, p, label, .stMarkdown, .stMarkdown p { color: #e0e0e0 !important; }
    h1, h2, h3 { color: #00ff9f !important; }
    .stSidebar { background-color: #1e1e1e !important; }
    .stSidebar .stMarkdown, .stSidebar p, .stSidebar label { color: #e0e0e0 !important; }
    div[data-testid="stSidebar"] *, div[data-testid="stSidebar"] label { color: #e0e0e0 !important; }
    .stSlider label, .stCheckbox label, .stMultiSelect label { color: #e0e0e0 !important; }
    div[data-testid="stDataFrame"] { background-color: #ffffff; border-radius: 4px; border: 1px solid #333; }
    .stDataFrame td, .stDataFrame th { color: #000000 !important; background-color: #ffffff !important; }
    .stMetric label { color: #e0e0e0 !important; }
    .stMetric value { color: #00ff9f !important; }
    .footer { color: #888; font-size: 0.85rem; margin-top: 2rem; }
    code, .mono { font-family: 'Consolas', monospace; color: #e0e0e0; }
    section[data-testid="stSidebar"] { background-color: #1e1e1e !important; }
    /* Expander: single outer border only; always dark (no flip on expand) */
    .st-expander, [data-testid="stExpander"] { border: 1px solid #666 !important; border-radius: 4px !important; background-color: #0e1117 !important; }
    .st-expanderHeader, .st-expanderContent, [data-testid="stExpander"] summary, [data-testid="stExpander"] .streamlit-expanderHeader { border: none !important; }
    .st-expanderHeader, [data-testid="stExpander"] summary, [data-testid="stExpander"] .streamlit-expanderHeader { background-color: #1e1e1e !important; color: #ffffff !important; }
    .st-expanderContent, [data-testid="stExpander"] div[data-testid="stExpanderDetails"] { background-color: #0e1117 !important; color: #e0e0e0 !important; }
    .streamlit-expanderContent { background-color: #0e1117 !important; color: #e0e0e0 !important; }
    [data-testid="stExpander"] summary svg, [data-testid="stExpander"] .streamlit-expanderHeader svg { fill: #00ff9f !important; stroke: #00ff9f !important; }
    /* Buttons: dark theme, readable on hover */
    .stDownloadButton button, .stButton button { background-color: #1e1e1e !important; color: #e0e0e0 !important; border: 1px solid #333 !important; }
    .stDownloadButton button:hover, .stButton button:hover { background-color: #2a2a2a !important; color: #ffffff !important; border-color: #00ff9f !important; }
    /* Inputs */
    .stTextInput input { background-color: #1e1e1e !important; color: #e0e0e0 !important; border-color: #333 !important; }
    /* Captions and labels: readable on dark */
    .stCaption, [data-testid="stCaptionContainer"] { color: #e0e0e0 !important; }
    /* File uploader: filename, size, remove icon – dark text on light bg, white on sidebar (dark) */
    div[data-testid="stFileUploaderFileName"], div[data-testid="stFileUploaderFileSize"],
    button[data-testid="stFileUploaderRemoveButton"] svg, .uploadedFileName, .uploadedFileSize, .stFileUploaderRemoveIcon { color: #000000 !important; }
    button[data-testid="stFileUploaderRemoveButton"] { background-color: transparent !important; }
    section[data-testid="stSidebar"] div[data-testid="stFileUploaderFileName"],
    section[data-testid="stSidebar"] div[data-testid="stFileUploaderFileSize"],
    section[data-testid="stSidebar"] .uploadedFileName, section[data-testid="stSidebar"] .uploadedFileSize,
    section[data-testid="stSidebar"] button[data-testid="stFileUploaderRemoveButton"] svg { color: #ffffff !important; }
    /* File size text: force visible (white/light) when on dark */
    .uploadedFileSize, div[data-testid="stFileUploaderFileSize"], span[data-testid="stFileUploaderFileSize"] { color: #ffffff !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data
def load_polished_or_refined():
    """Load polished CSVs if present, else refined; return (events_df, summary_df)."""
    polished_events = PROCESSED_DIR / "events_with_chains_polished.csv"
    polished_summary = PROCESSED_DIR / "chains_summary_polished.csv"
    refined_events = PROCESSED_DIR / "events_with_chains_refined.csv"
    refined_summary = PROCESSED_DIR / "chains_summary_refined.csv"

    if polished_events.exists() and polished_summary.exists():
        events = pd.read_csv(polished_events)
        summary = pd.read_csv(polished_summary)
        events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
        if "chain_tactic" not in events.columns:
            events = add_tactic_mapping(events)
        if "Tactic" not in summary.columns and "chain_tactic" in events.columns:
            summary = build_chains_summary_polished(events)
        return events, summary
    if refined_events.exists() and refined_summary.exists():
        events, summary = load_refined_data(refined_events, refined_summary)
        events = apply_polish_filters(events, summary, min_confidence=40)
        events = add_tactic_mapping(events)
        summary = build_chains_summary_polished(events)
        return events, summary
    return pd.DataFrame(), pd.DataFrame()


def build_summary_from_events(events_df: pd.DataFrame) -> pd.DataFrame:
    """Build chains summary from events (e.g. after upload)."""
    if events_df.empty:
        return pd.DataFrame()
    if "chain_tactic" not in events_df.columns:
        events_df = add_tactic_mapping(events_df)
    return build_chains_summary_polished(events_df)


def duration_human_readable(seconds: float) -> str:
    """Format duration in seconds as e.g. '2 min 15 sec' or '45 sec'."""
    if pd.isna(seconds) or seconds < 0:
        return ""
    s = int(seconds)
    if s < 60:
        return f"{s} sec"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m} min {s} sec"
    h, m = divmod(m, 60)
    return f"{h} h {m} min {s} sec"


# Display renames: internal column name -> title-case human-readable (for Raw Events table)
DISPLAY_RENAMES_EVENTS = {
    "chain_id": "Chain ID",
    "start_time": "Start Time",
    "end_time": "End Time",
    "duration": "Duration (seconds)",
    "num_events": "Num Events",
    "chain_techniques": "Techniques",
    "chain_tactic": "Tactic",
    "chain_confidence": "Chain Confidence (%)",
    "chain_explanation": "Explanation",
    "timestamp": "Timestamp",
    "event_type": "Event Type",
    "process_path": "Process Path",
    "cmdline": "Command Line",
}
# Hide from Raw Events (used only for coloring)
HIDE_COLUMNS_RAW = {"technique_color", "tactic_color"}


def _to_title_case(s: str) -> str:
    """Convert snake_case to Title Case for display."""
    return s.replace("_", " ").title()


def events_display_df(events_df: pd.DataFrame) -> pd.DataFrame:
    """Rename columns to title case, format confidence as percentage, hide color-only columns."""
    df = events_df.copy()
    drop = [c for c in HIDE_COLUMNS_RAW if c in df.columns]
    if drop:
        df = df.drop(columns=drop)
    renames = {k: v for k, v in DISPLAY_RENAMES_EVENTS.items() if k in df.columns}
    df = df.rename(columns=renames)
    # Any remaining snake_case columns -> Title Case
    extra = {c: _to_title_case(c) for c in df.columns if "_" in c}
    if extra:
        df = df.rename(columns=extra)
    if "Chain Confidence (%)" in df.columns and pd.api.types.is_numeric_dtype(df["Chain Confidence (%)"]):
        df["Chain Confidence (%)"] = df["Chain Confidence (%)"].apply(
            lambda x: f"{x:.0f}%" if pd.notna(x) and isinstance(x, (int, float)) else ""
        )
    return df


def summary_display_columns(summary: pd.DataFrame) -> pd.DataFrame:
    """Add human-readable Duration column for display (tooltip: duration in seconds)."""
    df = summary.copy()
    sec_col = None
    if "Duration (seconds)" in df.columns:
        sec_col = "Duration (seconds)"
    elif "Duration" in df.columns and pd.api.types.is_numeric_dtype(df["Duration"]):
        sec_col = "Duration"
        df["Duration (seconds)"] = df["Duration"]
    if sec_col is not None:
        df["Duration"] = df[sec_col].map(duration_human_readable)
    return df


def _conf_cell_style(row: pd.Series, conf_col: str = "Confidence Score") -> list:
    """Return one style for Confidence Score cell: green ≥80, yellow 50–79, red/gray <50."""
    try:
        c = float(row.get(conf_col, 100))
    except (TypeError, ValueError):
        c = 100
    if c >= 80:
        return ["background-color: #d4edda; color: #155724"]
    if c >= 50:
        return ["background-color: #fff3cd; color: #856404"]
    return ["background-color: #f8d7da; color: #721c24"]


def _table_style_confidence(df: pd.DataFrame, conf_col: str = "Confidence Score"):
    """Black text on white table; Confidence Score column gets colored background by tier (green/yellow/red)."""
    if conf_col not in df.columns:
        return df.style.set_properties(**{"color": "black", "background-color": "white"})
    return (
        df.style.set_properties(**{"color": "black", "background-color": "white"})
        .apply(lambda row: _conf_cell_style(row, conf_col), subset=[conf_col], axis=1)
    )


# Title and subtitle
st.title("MITRE ATT&CK Attack Chain Visualizer")
st.markdown("**From real Splunk Atomic Red Team logs**")

# Sidebar (filters that don't depend on data)
with st.sidebar:
    st.header("Filters")
    min_confidence = st.slider("Min Confidence Score", 0, 100, 40)
    min_chain_length = st.slider("Min Chain Length", 1, 10, 2)
    multi_event_only = st.checkbox("Show only multi-event chains", value=True)
    with st.expander("How It Works", expanded=False):
        st.markdown(
            "- **Upload** or use built-in Atomic Red Team logs.\n"
            "- Events are **grouped into process chains** using parent-child relationships and time proximity.\n"
            "- Chains are **mapped to MITRE ATT&CK** techniques/tactics with confidence scores.\n"
            "- **High-confidence chains (≥50%)** show likely attack sequences (e.g., Execution → Credential Access).\n"
            "- Use **filters** to focus on suspicious activity."
        )
    with st.expander("Background info", expanded=False):
        st.write(
            "High-confidence chains highlight potential attack sequences "
            "(Execution → Credential Access → Persistence)."
        )
    uploaded = st.file_uploader("Upload events CSV (optional)", type=["csv"])

# Load data
upload_success = False
if uploaded is not None:
    try:
        events_df = pd.read_csv(uploaded)
        if events_df.empty:
            raise ValueError("CSV has no data rows")
        events_df["timestamp"] = pd.to_datetime(events_df["timestamp"], errors="coerce")
        if "chain_benign_root_only" not in events_df.columns:
            events_df["chain_benign_root_only"] = False
        events_df = events_df[~events_df.get("chain_benign_root_only", pd.Series(False))]
        events_df = add_tactic_mapping(events_df)
        summary_df = build_summary_from_events(events_df)
        upload_success = True
    except pd.errors.ParserError:
        st.error("Cannot parse file – check for correct CSV formatting.")
        events_df, summary_df = load_polished_or_refined()
    except (ValueError, KeyError):
        st.error(
            "Error: Invalid CSV format or structure. Please ensure it has required columns "
            "(timestamp, process_path, cmdline, parent_process, etc.)."
        )
        events_df, summary_df = load_polished_or_refined()
    except Exception:
        st.error(
            "Error: Invalid CSV format or structure. Please ensure it has required columns "
            "(timestamp, process_path, cmdline, parent_process, etc.)."
        )
        events_df, summary_df = load_polished_or_refined()
else:
    events_df, summary_df = load_polished_or_refined()

if summary_df.empty or events_df.empty:
    st.warning(
        "No data loaded. Run chain_refine and chain_polish, or upload an events CSV. "
        "Expected: data/processed/events_with_chains_polished.csv (or refined)."
    )
    st.stop()

if upload_success:
    st.success("File uploaded and processed successfully.")

# Column names: polished uses "Chain ID", refined may use "chain_id"
summary_chain_col = "Chain ID" if "Chain ID" in summary_df.columns else "chain_id"
cid_col = "chain_id" if "chain_id" in events_df.columns else "Chain ID"
conf_col = "Confidence Score" if "Confidence Score" in summary_df.columns else "chain_confidence"
if "Num Events" not in summary_df.columns:
    n_events = events_df.groupby(cid_col).size()
    summary_df = summary_df.copy()
    summary_df["Num Events"] = summary_df[summary_chain_col].map(n_events).fillna(0).astype(int)
if conf_col not in summary_df.columns and "chain_confidence" in events_df.columns:
    first_conf = events_df.groupby(cid_col)["chain_confidence"].first()
    summary_df = summary_df.copy()
    summary_df[conf_col] = summary_df[summary_chain_col].map(first_conf)

# Apply filters in order: 1) Min Confidence, 2) Min Chain Length, 3) Multi-event only, 4) Tactic
summary_filtered = summary_df.copy()
if conf_col in summary_filtered.columns:
    summary_filtered = summary_filtered[summary_filtered[conf_col] >= min_confidence]
summary_filtered = summary_filtered[summary_filtered["Num Events"] >= min_chain_length]
if multi_event_only:
    summary_filtered = summary_filtered[summary_filtered["Num Events"] > 1]
tactic_options = sorted(summary_filtered["Tactic"].dropna().unique().tolist()) if "Tactic" in summary_filtered.columns else []
tactic_filter = st.sidebar.multiselect("Filter by Tactic", options=tactic_options)
if tactic_filter:
    summary_filtered = summary_filtered[summary_filtered["Tactic"].isin(tactic_filter)]
chain_ids = summary_filtered[summary_chain_col].tolist()
events_filtered = events_df[events_df[cid_col].isin(chain_ids)].copy()
summary_display = summary_display_columns(summary_filtered.copy())

# On-load preview: top 5 high-confidence chains + timeline preview
st.subheader("Preview: Top 5 high-confidence chains")
preview = summary_display.head(5)
if not preview.empty:
    st.dataframe(
        _table_style_confidence(preview),
        use_container_width=True,
        hide_index=True,
    )
    # Timeline preview (compact)
    if "Start Time" in preview.columns and "End Time" in preview.columns:
        prev_chains = preview[summary_chain_col].tolist()
        prev_events = events_filtered[events_filtered[cid_col].isin(prev_chains)]
        if not prev_events.empty and "timestamp" in prev_events.columns:
            prev_events = prev_events.copy()
            prev_events["Chain"] = prev_events[cid_col].astype(str)
            fig_preview = px.scatter(
                prev_events,
                x="timestamp",
                y="Chain",
                color="chain_tactic" if "chain_tactic" in prev_events.columns else cid_col,
                color_discrete_map=TACTIC_COLORS,
                hover_data=["chain_techniques", "chain_confidence", "process_path"] if "chain_techniques" in prev_events.columns else None,
                title="Timeline preview (top 5 chains)",
            )
            fig_preview.update_layout(
                template="plotly_dark",
                paper_bgcolor="#0e1117",
                plot_bgcolor="#1e1e1e",
                font=dict(color="#ffffff"),
                title_font=dict(color="#ffffff"),
                legend=dict(font=dict(color="#ffffff"), title_font=dict(color="#ffffff")),
                xaxis_title="Timestamp",
                yaxis_title="Chain ID",
                legend_title_text="Tactic",
                xaxis=dict(tickformat="%Y-%m-%d %H:%M:%S", title_font=dict(color="#ffffff"), tickfont=dict(color="#ffffff")),
                yaxis=dict(title_font=dict(color="#ffffff"), tickfont=dict(color="#ffffff")),
            )
            st.plotly_chart(fig_preview, use_container_width=True)
st.divider()

# Tabs
tab1, tab2, tab3 = st.tabs(["Chain Summary Table", "Interactive Timeline", "Raw Events"])

with tab1:
    st.subheader("Chain Summary")
    search = st.text_input("Search (Technique / Tactic / Explanation)", key="search_summary")
    st.caption("Press Enter after typing to apply search.")
    if search:
        mask = summary_display.astype(str).apply(lambda row: row.str.contains(search, case=False, na=False).any(), axis=1)
        summary_display = summary_display[mask]
    styled = _table_style_confidence(summary_display)
    st.dataframe(styled, use_container_width=True, hide_index=True)
    csv_export = summary_display.to_csv(index=False).encode("utf-8")
    st.download_button("Export summary as CSV", data=csv_export, file_name="chains_summary_export.csv", mime="text/csv")

with tab2:
    st.subheader("Interactive Timeline")
    if events_filtered.empty:
        st.info("No events after filters.")
    else:
        timeline_df = events_filtered.copy()
        timeline_df["Chain_label"] = timeline_df[cid_col].astype(str)
        color_col = "chain_tactic" if "chain_tactic" in timeline_df.columns else "tactic_color"
        # Cmdline snippet (first 120 chars) and full explanation for hover
        timeline_df["_cmdline_snippet"] = timeline_df.get("cmdline", pd.Series(dtype=object)).fillna("").astype(str).str[:120]
        timeline_df["_explanation"] = timeline_df.get("chain_explanation", pd.Series(dtype=object)).fillna("").astype(str)
        fig = px.scatter(
            timeline_df,
            x="timestamp",
            y="Chain_label",
            color=color_col,
            color_discrete_map=TACTIC_COLORS if color_col == "chain_tactic" else None,
            custom_data=["chain_techniques", "chain_confidence", "_cmdline_snippet", "_explanation"],
            title="Chains over time (color = Tactic)",
        )
        fig.update_traces(
            hovertemplate=(
                "<b>Chain ID</b>: %{y}<br>"
                "<b>Techniques</b>: %{customdata[0]}<br>"
                "<b>Tactic</b>: %{fullData.name}<br>"
                "<b>Confidence Score</b>: %{customdata[1]}<br>"
                "<b>Cmdline</b>: %{customdata[2]}<br>"
                "<b>Explanation</b>: %{customdata[3]}<extra></extra>"
            )
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="#0e1117",
            plot_bgcolor="#1e1e1e",
            font=dict(color="#ffffff"),
            title_font=dict(color="#ffffff"),
            legend=dict(font=dict(color="#ffffff"), title_font=dict(color="#ffffff")),
            xaxis=dict(tickformat="%Y-%m-%d %H:%M:%S", title_font=dict(color="#ffffff"), tickfont=dict(color="#ffffff")),
            yaxis=dict(title_font=dict(color="#ffffff"), tickfont=dict(color="#ffffff")),
            xaxis_title="Timestamp",
            yaxis_title="Chain ID",
            legend_title_text="Tactic",
            height=600,
        )
        st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.subheader("Raw Events (filtered)")
    events_display = events_display_df(events_filtered)
    # Black text on white; Chain Confidence (%) gets same green/yellow/red tiers as summary
    raw_conf_col = "Chain Confidence (%)"
    if raw_conf_col in events_display.columns:
        def _raw_conf_style(row):
            try:
                s = str(row.get(raw_conf_col, "") or "").replace("%", "").strip()
                c = float(s) if s else 100
            except (TypeError, ValueError):
                c = 100
            if c >= 80:
                return ["background-color: #d4edda; color: #155724"]
            if c >= 50:
                return ["background-color: #fff3cd; color: #856404"]
            return ["background-color: #f8d7da; color: #721c24"]
        raw_styled = (
            events_display.style.set_properties(**{"color": "black", "background-color": "white"})
            .apply(_raw_conf_style, subset=[raw_conf_col], axis=1)
        )
    else:
        raw_styled = events_display.style.set_properties(**{"color": "black", "background-color": "white"})
    st.dataframe(raw_styled, use_container_width=True, hide_index=True)

# Footer
st.markdown(
    '<p class="footer">Techniques covered: T1059.001 (Execution), T1003.* (Credential Access), T1547.001 (Persistence)</p>',
    unsafe_allow_html=True,
)
