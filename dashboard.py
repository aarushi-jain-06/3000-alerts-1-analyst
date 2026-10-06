import streamlit as st
import pandas as pd
import json
import os
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ==============================================================================
# PAGE CONFIG & CSS
# ==============================================================================
st.set_page_config(
    page_title="SOC Triage Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CSS = """
<style>
    /* Design System Colors */
    :root {
        --background: #0B0D10;
        --sidebar: #101318;
        --surface: #15191F;
        --surface-elevated: #1B2028;
        --border: #292F38;
        --text-primary: #F1F3F5;
        --text-secondary: #A0A8B4;
        --text-muted: #697382;
        --accent: #6EA8FE;
        --critical: #EF4444;
        --high: #F97316;
        --medium: #EAB308;
        --low: #22C55E;
    }
    
    /* Apply Backgrounds and Text Colors */
    .stApp {
        background-color: var(--background);
        color: var(--text-primary);
        font-family: 'Inter', sans-serif;
    }
    [data-testid="stSidebar"] {
        background-color: var(--sidebar);
    }
    
    /* Metrics Cards */
    [data-testid="stMetric"] {
        background-color: var(--surface);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 15px;
    }
    [data-testid="stMetricValue"] {
        color: var(--text-primary);
    }
    [data-testid="stMetricLabel"] {
        color: var(--text-secondary);
    }
    
    /* Custom Badges */
    .badge {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }
    .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }
    .badge-low { background-color: rgba(34, 197, 94, 0.2); color: var(--low); border: 1px solid var(--low); }
    .badge-ml { background-color: rgba(110, 168, 254, 0.2); color: var(--accent); border: 1px solid var(--accent); margin-left: 5px; font-size: 0.7rem; }
    
    .status-amber { color: #F59E0B; font-weight: bold; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ==============================================================================
# DATA LOADING
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")

@st.cache_data
def load_data():
    data = {
        'incidents': [],
        'review_queue': pd.DataFrame(),
        'alerts': pd.DataFrame(),
        'retrain_history': pd.DataFrame(),
        'mttt_metrics': "",
        'assets': {},
        'metrics': {}
    }
    
    # Load Incidents
    inc_path = os.path.join(OUTPUTS_DIR, "incidents.json")
    if os.path.exists(inc_path):
        with open(inc_path, 'r') as f:
            data['incidents'] = json.load(f)
            
    # Load Review Queue
    rq_path = os.path.join(OUTPUTS_DIR, "review_queue.csv")
    if os.path.exists(rq_path):
        data['review_queue'] = pd.read_csv(rq_path)
        
    # Load Alerts
    al_path = os.path.join(OUTPUTS_DIR, "alerts.csv")
    if os.path.exists(al_path):
        data['alerts'] = pd.read_csv(al_path)
        
    # Load Retrain History
    rh_path = os.path.join(BASE_DIR, "retrain_history.csv")
    if os.path.exists(rh_path):
        data['retrain_history'] = pd.read_csv(rh_path)
        
    # Load MTTT Metrics
    mttt_path = os.path.join(OUTPUTS_DIR, "mttt_metrics.md")
    if os.path.exists(mttt_path):
        with open(mttt_path, 'r') as f:
            data['mttt_metrics'] = f.read()

    metrics_path = os.path.join(OUTPUTS_DIR, "metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r', encoding='utf-8') as f:
            data['metrics'] = json.load(f)
            
    # Load Assets (from assets.py dynamically if possible, or static fallback)
    try:
        import sys
        if BASE_DIR not in sys.path:
            sys.path.append(BASE_DIR)
        import assets
        data['assets'] = assets.ASSET_REGISTRY
    except:
        pass
        
    return data

data = load_data()
metrics = data.get('metrics', {})
model_f1 = 0.0
try:
    from ml_classifier import get_model_info
    model_f1 = get_model_info().get('f1') or 0.0
except Exception:
    pass

# Helper for Risk Badge
def get_risk_badge(tier):
    tier_lower = tier.lower()
    return f'<span class="badge badge-{tier_lower}">{tier.upper()}</span>'

# ==============================================================================
# SIDEBAR
# ==============================================================================
st.sidebar.markdown("### 🛡️ SOC Triage Pipeline")
page = st.sidebar.radio("Navigation", [
    "Command Center",
    "Incidents Explorer",
    "Predict",
    "Review Queue",
    "Analytics",
    "Assets & MITRE"
])
st.sidebar.markdown("---")
st.sidebar.markdown(f"<div style='text-align: center;'><small>🤖 Model Status: ONLINE<br>RandomForest F1={model_f1:.4f}</small></div>", unsafe_allow_html=True)

# ==============================================================================
# PAGES
# ==============================================================================

if page == "Command Center":
    st.markdown("## 3,000 Alerts, One Analyst")
    st.markdown("<p style='color: var(--text-secondary);'>AI-driven alert correlation and triaging.</p>", unsafe_allow_html=True)
    
    # Calculate stats
    total_alerts = int(metrics.get('n_alerts', len(data['alerts'])))
    inc_df = pd.DataFrame(data['incidents'])
    total_incidents = len(inc_df) if not inc_df.empty else 0
    noise_red = ((total_alerts - total_incidents) / total_alerts * 100) if total_alerts else 0
    
    crit_count = len(inc_df[inc_df['risk_tier'] == 'CRITICAL']) if not inc_df.empty else 0
    high_count = len(inc_df[inc_df['risk_tier'] == 'HIGH']) if not inc_df.empty else 0
    cross_asset_count = len(inc_df[inc_df['assets'].apply(lambda x: isinstance(x, list) and len(x) > 1)]) if not inc_df.empty and 'assets' in inc_df.columns else 0
    
    col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
    col1.metric("Total Alerts", f"{total_alerts:,}")
    col2.metric("Incidents", f"{total_incidents:,}")
    col3.metric("Noise Reduction", f"{noise_red:.1f}%")
    col4.metric("MTTT Reduction", f"{metrics.get('mttt_reduction_pct_per_alert', 0):.1f}%")
    col5.metric("Critical", crit_count)
    col6.metric("High", high_count)
    col7.metric("Cross-Asset", cross_asset_count)
    
    st.markdown("---")
    c1, c2 = st.columns([1, 2])
    
    with c1:
        st.markdown("### Severity Distribution")
        if not inc_df.empty:
            tier_counts = inc_df['risk_tier'].value_counts().reset_index()
            tier_counts.columns = ['Tier', 'Count']
            color_map = {'CRITICAL': '#EF4444', 'HIGH': '#F97316', 'MEDIUM': '#EAB308', 'LOW': '#22C55E'}
            fig = px.pie(tier_counts, values='Count', names='Tier', hole=0.6, 
                         color='Tier', color_discrete_map=color_map, template='plotly_dark')
            fig.update_layout(margin=dict(t=20, b=20, l=20, r=20), showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
            
        st.info(f"🤖 **Model Info:** RandomForest F1={model_f1:.4f} | Trained on CICIDS2017 | Hybrid confidence")
        
        st.markdown("### MTTT Comparison (min)")
        fig_bar = go.Figure(data=[
            go.Bar(name='MTTT', x=['Baseline', 'Pipeline'], y=[metrics.get('baseline_mttt_per_alert_min', 0), metrics.get('pipeline_mttt_per_alert_min', 0)], marker_color=['#697382', '#6EA8FE'])
        ])
        fig_bar.update_layout(template='plotly_dark', margin=dict(t=20, b=20, l=20, r=20), height=250)
        st.plotly_chart(fig_bar, use_container_width=True)

    with c2:
        st.markdown("### Top 10 Incidents")
        if not inc_df.empty:
            top10 = inc_df.sort_values(by='risk_score', ascending=False).head(10)
            
            # Build custom table
            html = "<table style='width: 100%; text-align: left; border-collapse: collapse;'>"
            html += "<tr style='border-bottom: 1px solid var(--border);'><th style='padding: 8px;'>ID</th><th>Asset</th><th>Tier</th><th>Score</th><th>Alerts</th><th>Top Tactic</th></tr>"
            
            for _, row in top10.iterrows():
                badge = get_risk_badge(row['risk_tier'])
                top_tactic = row['tactics'][0] if isinstance(row['tactics'], list) and len(row['tactics'])>0 else ""
                html += f"<tr style='border-bottom: 1px solid var(--border);'>\
                <td style='padding: 8px;'>{row['incident_id']}</td>\
                <td>{row['asset_id']}</td>\
                <td>{badge}</td>\
                <td>{row['risk_score']:.2f}</td>\
                <td>{row['alert_count']}</td>\
                <td>{top_tactic}</td>\
                </tr>"
            html += "</table>"
            st.markdown(html, unsafe_allow_html=True)

elif page == "Incidents Explorer":
    st.markdown("## Incidents Explorer")
    
    inc_df = pd.DataFrame(data['incidents'])
    if not inc_df.empty:
        # Filters
        c1, c2, c3 = st.columns(3)
        with c1:
            tiers = st.multiselect("Risk Tier", options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default=['CRITICAL', 'HIGH', 'MEDIUM'])
        with c2:
            assets = st.multiselect("Asset ID", options=inc_df['asset_id'].unique())
        with c3:
            min_score = st.slider("Min Risk Score", 0.0, float(inc_df['risk_score'].max()), 0.0)
            
        filtered = inc_df[
            (inc_df['risk_tier'].isin(tiers) if tiers else True) &
            (inc_df['asset_id'].isin(assets) if assets else True) &
            (inc_df['risk_score'] >= min_score)
        ]
        
        # Table of all incidents
        st.dataframe(filtered[['incident_id', 'risk_tier', 'risk_score', 'asset_id', 'alert_count', 'start_time']], use_container_width=True, hide_index=True)
        
        # Selection
        selected_id = st.selectbox("Select Incident for Details", options=filtered['incident_id'].tolist(), key='selected_incident')
        
        if selected_id:
            st.markdown("---")
            inc = filtered[filtered['incident_id'] == selected_id].iloc[0]
            
            st.markdown(f"### {inc['incident_id']} {get_risk_badge(inc['risk_tier'])}", unsafe_allow_html=True)
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Risk Score", f"{inc['risk_score']:.2f}")
            sc2.metric("Asset", inc['asset_id'])
            sc3.metric("Alerts", inc['alert_count'])
            sc4.metric("Time", f"{inc['start_time'][:16].replace('T', ' ')}")

            if isinstance(inc.get('assets', []), list):
                impacted = ", ".join(inc.get('assets', []))
            else:
                impacted = str(inc.get('assets', inc.get('asset_id', '')))
            st.info(f"🔗 **Correlation:** {inc.get('correlation_method', 'asset_time_graph')}  |  **Impacted assets:** {impacted}")
            
            st.markdown(f"**Brief:** {inc.get('brief', '')}")
            
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**MITRE ATT&CK Techniques:**")
                tech_html = " ".join([f"<span class='badge' style='background: var(--surface-elevated); border: 1px solid var(--border);'>{t}</span>" for t in inc.get('techniques', [])])
                st.markdown(tech_html, unsafe_allow_html=True)
                
                st.markdown("<br>**Tactics Kill-Chain:**", unsafe_allow_html=True)
                st.markdown(" → ".join(inc.get('tactics', [])))
                
            with col_b:
                st.markdown("**Predicted Next Stage:**")
                st.warning(inc.get('predicted_next_stage', 'N/A'))
                
                conf = inc.get('confidence', 0)
                ml = inc.get('ml_confidence', False)
                ml_badge = "<span class='badge-ml'>ML-Powered</span>" if ml else ""
                st.markdown(f"**Confidence:** {conf*100:.1f}% {ml_badge}", unsafe_allow_html=True)
                
                st.markdown(f"**Alert IDs:** {', '.join(inc.get('alert_ids', [])[:10])}...")

            st.markdown("### Score explanation")
            score_parts = {
                "Asset criticality weight": inc.get("asset_criticality_weight", "N/A"),
                "Maximum severity": inc.get("max_severity", "N/A"),
                "Confidence": inc.get("confidence", "N/A"),
                "Kill-chain bonus": inc.get("chain_bonus", "N/A"),
                "ML confidence enabled": inc.get("ml_confidence", False),
            }
            st.dataframe(pd.DataFrame([score_parts]), use_container_width=True, hide_index=True)

            trace = inc.get("investigation_trace", [])
            if trace:
                with st.expander("Investigation trace — high/critical incident"):
                    for step in trace:
                        st.markdown(f"**Step {step.get('step')}: `{step.get('tool')}`**")
                        st.json(step.get("result", {}))

elif page == "Review Queue":
    st.markdown("## Review Queue")
    rq = data['review_queue']
    if not rq.empty:
        pending = len(rq[rq['disposition'] == 'PENDING'])
        false_pos = len(rq[rq['auto_suggested_disposition'] == 'FALSE_POSITIVE'])
        reviewed = len(rq[rq['disposition'] != 'PENDING'])
        
        c1, c2, c3 = st.columns(3)
        c1.metric("Pending Review", pending)
        c2.metric("Suggested FALSE_POSITIVE", false_pos)
        c3.metric("Reviewed", reviewed)
        
        st.markdown("*Note: Dispositions require analyst confirmation — nothing auto-closes*")
        
        # Filters
        c4, c5 = st.columns(2)
        with c4:
            disp_filter = st.multiselect("Disposition", options=rq['disposition'].unique(), default=['PENDING'])
        with c5:
            tier_filter = st.multiselect("Risk Tier", options=rq['risk_tier'].unique())
            
        f_rq = rq[
            (rq['disposition'].isin(disp_filter) if disp_filter else True) &
            (rq['risk_tier'].isin(tier_filter) if tier_filter else True)
        ]
        
        # Custom HTML table for specific coloring
        html = "<table style='width: 100%; text-align: left; border-collapse: collapse;'>"
        html += "<tr style='border-bottom: 1px solid var(--border);'><th style='padding: 8px;'>ID</th><th>Tier</th><th>Score</th><th>Asset</th><th>Auto-Suggest</th><th>Disposition</th></tr>"
        
        for _, row in f_rq.iterrows():
            badge = get_risk_badge(row['risk_tier'])
            sug = row['auto_suggested_disposition']
            sug_display = f"<span class='status-amber'>Auto-suggested: {sug}</span>" if sug == 'FALSE_POSITIVE' else str(sug)
            html += f"<tr style='border-bottom: 1px solid var(--border);'>\
            <td style='padding: 8px;'>{row['incident_id']}</td>\
            <td>{badge}</td>\
            <td>{row['risk_score']:.2f}</td>\
            <td>{row['asset_id']}</td>\
            <td>{sug_display}</td>\
            <td>{row['disposition']}</td>\
            </tr>"
        html += "</table>"
        st.markdown(html, unsafe_allow_html=True)

        st.markdown("### Apply analyst disposition")
        edit_col1, edit_col2 = st.columns(2)
        with edit_col1:
            edit_id = st.selectbox("Incident", rq["incident_id"].tolist(), key="edit_incident")
            edit_disposition = st.selectbox("Disposition", ["TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATED", "MERGE"], key="edit_disposition")
        with edit_col2:
            edit_analyst = st.text_input("Analyst name", value="analyst", key="edit_analyst")
            edit_notes = st.text_input("Notes", key="edit_notes")
        if st.button("Save disposition", type="primary"):
            from human_loop import apply_disposition
            queue_records = rq.to_dict("records")
            apply_disposition(queue_records, edit_id, edit_disposition, edit_analyst, edit_notes)
            pd.DataFrame(queue_records).to_csv(os.path.join(OUTPUTS_DIR, "review_queue.csv"), index=False)
            st.cache_data.clear()
            st.success("Disposition saved to the audit queue and feedback log.")
            st.rerun()
    else:
        st.warning("Review queue data not found.")

elif page == "Analytics":
    st.markdown("## Analytics")
    
    saved = metrics.get('baseline_total_hours', 0) - metrics.get('pipeline_total_hours', 0)
    st.success(f"🎯 **Analyst time saved: {saved:.1f} hours ({metrics.get('analyst_time_reduction_pct', 0):.1f}% reduction)**")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Incident Tier Distribution")
        inc_df = pd.DataFrame(data['incidents'])
        if not inc_df.empty:
            tier_counts = inc_df['risk_tier'].value_counts().reset_index()
            tier_counts.columns = ['Tier', 'Count']
            color_map = {'CRITICAL': '#EF4444', 'HIGH': '#F97316', 'MEDIUM': '#EAB308', 'LOW': '#22C55E'}
            fig = px.bar(tier_counts, x='Tier', y='Count', color='Tier', color_discrete_map=color_map, template='plotly_dark')
            st.plotly_chart(fig, use_container_width=True)
            
    with col2:
        st.markdown("### MTTT Before/After")
        fig_bar = go.Figure(data=[
            go.Bar(name='Baseline', x=['MTTT (min)'], y=[metrics.get('baseline_mttt_per_alert_min', 0)], marker_color='#697382'),
            go.Bar(name='Pipeline', x=['MTTT (min)'], y=[metrics.get('pipeline_mttt_per_alert_min', 0)], marker_color='#6EA8FE')
        ])
        fig_bar.update_layout(template='plotly_dark', barmode='group')
        st.plotly_chart(fig_bar, use_container_width=True)
        
    st.markdown("### Alert Type Frequency")
    al_df = data['alerts']
    if not al_df.empty:
        type_counts = al_df['alert_type'].value_counts().head(15).reset_index()
        type_counts.columns = ['Alert Type', 'Count']
        fig_types = px.bar(type_counts, x='Count', y='Alert Type', orientation='h', template='plotly_dark')
        fig_types.update_layout(yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_types, use_container_width=True)
        
    st.markdown("### Asset Heat Map")
    if not inc_df.empty:
        asset_stats = inc_df.groupby('asset_id').agg({'incident_id':'count', 'risk_score':'mean'}).reset_index()
        asset_stats.columns = ['Asset', 'Incident Count', 'Avg Risk Score']
        fig_heat = px.treemap(asset_stats, path=['Asset'], values='Incident Count', color='Avg Risk Score', 
                              color_continuous_scale='Reds', template='plotly_dark')
        st.plotly_chart(fig_heat, use_container_width=True)

    st.markdown("### Model Training History")
    rh = data['retrain_history']
    if not rh.empty:
        st.dataframe(rh, use_container_width=True, hide_index=True)

elif page == "Assets & MITRE":
    st.markdown("## Assets & MITRE")
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("### Asset Registry")
        inc_df = pd.DataFrame(data['incidents'])
        
        asset_metrics = {}
        if not inc_df.empty:
            for _, r in inc_df.iterrows():
                aid = r['asset_id']
                if aid not in asset_metrics:
                    asset_metrics[aid] = {'count': 0, 'score_sum': 0}
                asset_metrics[aid]['count'] += 1
                asset_metrics[aid]['score_sum'] += r['risk_score']
                
        assets_data = []
        for aid, info in data['assets'].items():
            m = asset_metrics.get(aid, {'count': 0, 'score_sum': 0})
            avg_score = (m['score_sum'] / m['count']) if m['count'] > 0 else 0
            assets_data.append({
                'Asset ID': aid,
                'Type': info['type'],
                'Criticality': info['criticality'],
                'Incidents': m['count'],
                'Avg Risk Score': round(avg_score, 2)
            })
            
        ass_df = pd.DataFrame(assets_data)
        if not ass_df.empty:
            ass_df = ass_df.sort_values(by='Incidents', ascending=False)
            html = "<table style='width: 100%; text-align: left; border-collapse: collapse;'>"
            html += "<tr style='border-bottom: 1px solid var(--border);'><th style='padding: 8px;'>ID</th><th>Type</th><th>Criticality</th><th>Incidents</th><th>Avg Risk</th></tr>"
            
            for _, row in ass_df.iterrows():
                badge = get_risk_badge(row['Criticality'])
                html += f"<tr style='border-bottom: 1px solid var(--border);'>\
                <td style='padding: 8px;'>{row['Asset ID']}</td>\
                <td>{row['Type']}</td>\
                <td>{badge}</td>\
                <td>{row['Incidents']}</td>\
                <td>{row['Avg Risk Score']}</td>\
                </tr>"
            html += "</table>"
            st.markdown(html, unsafe_allow_html=True)
            
    with col_b:
        st.markdown("### MITRE ATT&CK Coverage")
        al_df = data['alerts']
        if not al_df.empty:
            mitre = al_df[['technique_id', 'technique_name', 'tactic']].drop_duplicates()
            counts = al_df['technique_id'].value_counts().reset_index()
            counts.columns = ['technique_id', 'frequency']
            mitre = pd.merge(mitre, counts, on='technique_id').sort_values(by='frequency', ascending=False)
            
            html = "<table style='width: 100%; text-align: left; border-collapse: collapse;'>"
            html += "<tr style='border-bottom: 1px solid var(--border);'><th style='padding: 8px;'>Technique ID</th><th>Name</th><th>Tactic</th><th>Frequency</th></tr>"
            
            for _, row in mitre.iterrows():
                html += f"<tr style='border-bottom: 1px solid var(--border);'>\
                <td style='padding: 8px;'><span class='badge' style='background: var(--surface-elevated); border: 1px solid var(--border);'>{row['technique_id']}</span></td>\
                <td>{row['technique_name']}</td>\
                <td>{row['tactic']}</td>\
                <td>{row['frequency']}</td>\
                </tr>"
            html += "</table>"
            st.markdown(html, unsafe_allow_html=True)

elif page == "Predict":
    st.markdown("## 🔍 Predict — Live Alert Classification")
    st.markdown(
        "<p style='color: var(--text-secondary);'>"
        "Upload a CSV of alerts or enter a single alert manually. "
        "The trained RandomForest model (F1=0.9567, CICIDS2017) will predict "
        "maliciousness probability for each alert and estimate a risk tier."
        "</p>", unsafe_allow_html=True
    )

    # Load ML model info
    try:
        import sys as _sys
        if BASE_DIR not in _sys.path:
            _sys.path.insert(0, BASE_DIR)
        from ml_classifier import predict_malicious_proba, get_model_info
        from scoring import risk_tier
        model_info = get_model_info()
        ml_ready = model_info["available"]
    except Exception as _e:
        ml_ready = False
        model_info = {}

    if ml_ready:
        st.success(f"🤖 Model loaded: **{model_info['model']}** | F1={model_info['f1']:.4f} | {model_info['n_features']} features")
    else:
        st.error("Model not loaded — run `python train_classifier.py` first.")

    st.markdown("---")
    tab1, tab2 = st.tabs(["📁 Upload CSV", "✏️ Manual Entry"])

    # ── TAB 1: CSV Upload ──────────────────────────────────────────────────────
    with tab1:
        st.markdown("### Upload Alert CSV")
        st.markdown(
            "Required columns: `alert_type`, `base_severity`, `false_positive_rate`, `tactic`  \n"
            "Optional: `alert_id`, `asset_id`, `timestamp`, `src_ip`, `dst_ip`"
        )

        # Download sample template
        sample_data = pd.DataFrame([
            {"alert_id": "SAMPLE-001", "asset_id": "DC01", "timestamp": "2026-09-26T08:04:38",
             "alert_type": "lsass_access",          "base_severity": 9,  "false_positive_rate": 0.20, "tactic": "Credential Access",      "src_ip": "10.20.1.5",  "dst_ip": "10.20.0.1"},
            {"alert_id": "SAMPLE-002", "asset_id": "DC01", "timestamp": "2026-09-26T08:07:12",
             "alert_type": "ransomware_note_created","base_severity": 10, "false_positive_rate": 0.05, "tactic": "Impact",                 "src_ip": "10.20.1.5",  "dst_ip": "185.220.10.1"},
            {"alert_id": "SAMPLE-003", "asset_id": "PRINT-SRV01", "timestamp": "2026-09-26T09:00:00",
             "alert_type": "usb_device_inserted",   "base_severity": 2,  "false_positive_rate": 0.85, "tactic": "Initial Access",         "src_ip": "10.20.5.20", "dst_ip": "10.20.5.20"},
            {"alert_id": "SAMPLE-004", "asset_id": "VPN-GW01", "timestamp": "2026-09-26T10:15:00",
             "alert_type": "c2_beacon_blocked",      "base_severity": 8,  "false_positive_rate": 0.30, "tactic": "Command and Control",    "src_ip": "10.20.2.10", "dst_ip": "185.220.200.5"},
            {"alert_id": "SAMPLE-005", "asset_id": "TEST-VM07", "timestamp": "2026-09-26T11:30:00",
             "alert_type": "av_signature_hit",       "base_severity": 3,  "false_positive_rate": 0.75, "tactic": "Execution",              "src_ip": "10.20.9.99", "dst_ip": "10.20.9.99"},
        ])
        sample_csv = sample_data.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Download Sample Template CSV", sample_csv,
                           "sample_alerts_template.csv", "text/csv")

        uploaded = st.file_uploader("Upload your alerts CSV", type=["csv"])

        if uploaded:
            try:
                df_up = pd.read_csv(uploaded)
                st.markdown(f"**Loaded {len(df_up)} alerts.** Preview:")
                st.dataframe(df_up.head(5), use_container_width=True, hide_index=True)

                required = {"alert_type", "base_severity", "false_positive_rate", "tactic"}
                missing = required - set(df_up.columns)
                if missing:
                    st.error(f"Missing required columns: {missing}")
                elif not ml_ready:
                    st.error("ML model not available.")
                else:
                    if st.button("🚀 Run Predictions", type="primary"):
                        with st.spinner("Running ML inference..."):
                            results = []
                            for _, row in df_up.iterrows():
                                alert = row.to_dict()
                                proba = predict_malicious_proba(alert)
                                static_conf = round(1 - float(alert.get("false_positive_rate", 0.5)), 3)
                                # Hybrid: ML boost only
                                if proba is not None and proba > 0.5:
                                    conf = min(static_conf + (proba - 0.5) * 0.4, 0.99)
                                else:
                                    conf = static_conf

                                sev  = float(alert.get("base_severity", 5))
                                # Simple tier estimate (single alert, asset_w=5 default)
                                asset_id = str(alert.get("asset_id", ""))
                                try:
                                    from assets import criticality_weight
                                    aw = criticality_weight(asset_id)
                                except Exception:
                                    aw = 5
                                score = round(aw * sev * conf, 2)
                                tier  = risk_tier(score)

                                results.append({
                                    "alert_id":            alert.get("alert_id", "—"),
                                    "asset_id":            alert.get("asset_id", "—"),
                                    "alert_type":          alert.get("alert_type", "—"),
                                    "tactic":              alert.get("tactic", "—"),
                                    "base_severity":       sev,
                                    "ml_malicious_proba":  round(proba, 4) if proba else "N/A",
                                    "confidence":          round(conf, 3),
                                    "risk_score":          score,
                                    "risk_tier":           tier,
                                })

                        res_df = pd.DataFrame(results)
                        st.markdown("### Prediction Results")

                        # Summary KPIs
                        k1, k2, k3, k4 = st.columns(4)
                        k1.metric("Total Alerts",  len(res_df))
                        k2.metric("CRITICAL",       len(res_df[res_df["risk_tier"] == "CRITICAL"]))
                        k3.metric("HIGH",           len(res_df[res_df["risk_tier"] == "HIGH"]))
                        k4.metric("LOW / MEDIUM",   len(res_df[res_df["risk_tier"].isin(["LOW","MEDIUM"])]))

                        # Colored table
                        html = "<table style='width:100%;border-collapse:collapse;font-size:0.85rem;'>"
                        html += "<tr style='border-bottom:1px solid var(--border);'>" + "".join(
                            f"<th style='padding:8px;text-align:left;'>{c}</th>"
                            for c in ["Alert ID","Asset","Type","Tactic","Sev","ML Proba","Confidence","Score","Tier"]
                        ) + "</tr>"
                        for _, r in res_df.iterrows():
                            badge = get_risk_badge(r["risk_tier"])
                            conf_pct = int(r["confidence"]*100)
                            conf_bar = (f"<div style='background:var(--border);border-radius:3px;height:6px;margin-top:3px;'>"
                                        f"<div style='width:{conf_pct}%;background:#6EA8FE;height:6px;border-radius:3px;'></div></div>")
                            html += (f"<tr style='border-bottom:1px solid var(--border);'>"
                                     f"<td style='padding:8px;font-family:monospace;'>{r['alert_id']}</td>"
                                     f"<td style='padding:8px;'>{r['asset_id']}</td>"
                                     f"<td style='padding:8px;'>{r['alert_type']}</td>"
                                     f"<td style='padding:8px;'>{r['tactic']}</td>"
                                     f"<td style='padding:8px;'>{r['base_severity']}</td>"
                                     f"<td style='padding:8px;'>{r['ml_malicious_proba']}</td>"
                                     f"<td style='padding:8px;'>{conf_pct}%{conf_bar}</td>"
                                     f"<td style='padding:8px;'>{r['risk_score']}</td>"
                                     f"<td style='padding:8px;'>{badge}</td>"
                                     f"</tr>")
                        html += "</table>"
                        st.markdown(html, unsafe_allow_html=True)

                        # Download results
                        st.download_button(
                            "⬇️ Download Predictions CSV",
                            res_df.to_csv(index=False).encode("utf-8"),
                            "predictions_output.csv", "text/csv"
                        )
            except Exception as e:
                st.error(f"Error reading file: {e}")

    # ── TAB 2: Manual Entry ────────────────────────────────────────────────────
    with tab2:
        st.markdown("### Single Alert Manual Entry")

        ALERT_TYPES = [
            "lsass_access", "ransomware_note_created", "c2_beacon_blocked",
            "powershell_encoded_cmd", "impossible_travel_login", "failed_logon_spike",
            "dns_tunneling_suspected", "port_scan_detected", "registry_run_key_mod",
            "new_scheduled_task", "av_signature_hit", "usb_device_inserted", "vpn_geo_anomaly"
        ]
        TACTICS = [
            "Credential Access", "Impact", "Command and Control", "Execution",
            "Defense Evasion / Initial Access", "Persistence", "Discovery",
            "Initial Access"
        ]

        col_a, col_b = st.columns(2)
        with col_a:
            m_alert_type  = st.selectbox("Alert Type", ALERT_TYPES)
            m_asset       = st.text_input("Asset ID", value="DC01")
            m_severity    = st.slider("Base Severity", 1, 10, 7)
        with col_b:
            m_tactic      = st.selectbox("Tactic", TACTICS)
            m_fp_rate     = st.slider("False Positive Rate", 0.0, 1.0, 0.30, 0.05)
            m_src_ip      = st.text_input("Source IP (optional)", value="10.20.1.5")

        if st.button("🔬 Predict This Alert", type="primary"):
            if not ml_ready:
                st.error("ML model not available.")
            else:
                alert = {
                    "alert_type": m_alert_type, "asset_id": m_asset,
                    "base_severity": m_severity, "false_positive_rate": m_fp_rate,
                    "tactic": m_tactic, "src_ip": m_src_ip,
                }
                proba = predict_malicious_proba(alert)
                static_conf = round(1 - m_fp_rate, 3)
                if proba is not None and proba > 0.5:
                    conf = min(static_conf + (proba - 0.5) * 0.4, 0.99)
                else:
                    conf = static_conf

                try:
                    from assets import criticality_weight
                    aw = criticality_weight(m_asset)
                except Exception:
                    aw = 5
                score = round(aw * m_severity * conf, 2)
                tier  = risk_tier(score)

                st.markdown("---")
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("ML Malicious Proba",  f"{proba:.4f}" if proba else "N/A")
                r2.metric("Confidence",           f"{int(conf*100)}%")
                r3.metric("Risk Score",           score)
                r4.metric("Risk Tier",            tier)

                st.markdown(f"**Verdict:** {get_risk_badge(tier)}", unsafe_allow_html=True)
                if tier in ("CRITICAL", "HIGH"):
                    st.error(f"⚠️ HIGH PRIORITY — Immediate analyst review required.")
                elif tier == "MEDIUM":
                    st.warning("Review within shift.")
                else:
                    st.success("Low urgency — bulk review at end of shift.")

                st.info(f"**Reasoning:** Asset criticality weight={aw} | Severity={m_severity} | "
                        f"Confidence={conf:.3f} (static {static_conf:.3f}"
                        + (f" + ML boost {round(conf-static_conf,3):.3f}" if conf > static_conf else "")
                        + f") | Score={score} = {aw}×{m_severity}×{conf:.3f}")

# Footer
st.markdown(f"<br><br><hr><div style='text-align: center; color: var(--text-muted);'><small>SOC Triage Pipeline | Microsoft Hackathon 2026 | RandomForest F1={model_f1:.4f}</small></div>", unsafe_allow_html=True)
