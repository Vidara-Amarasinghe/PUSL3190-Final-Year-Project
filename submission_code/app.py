import streamlit as st

pg = st.navigation([
    st.Page("pages/1_Dashboard.py",    title="Dashboard",          icon="🛡️"),
    st.Page("pages/2_Attacks.py",      title=" Attack Management",   icon="🚨"),
    st.Page("pages/3_Log_Analysis.py", title=" Log File Analysis",   icon="📂"),
    st.Page("pages/4_Evaluation.py",   title=" ML Evaluation",       icon="📊"),
])

pg.run()
