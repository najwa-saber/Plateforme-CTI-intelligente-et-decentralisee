"""Streamlit entry point - navigation between the platform pages."""
import streamlit as st

st.set_page_config(page_title="CTI Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="auto")  # auto: open on desktop, collapsed on phones

# The theme (components/theme.py) is applied by ui.setup() at the top of every page, i.e. AFTER
# st.navigation: writing query parameters before st.navigation would reset deep links to the default page.

pages = [
    st.Page("views/dashboard.py", title="Dashboard général", icon=":material/dashboard:", default=True),
    st.Page("views/import_cti.py", title="Importation CTI", icon=":material/upload_file:"),
    st.Page("views/analysis.py", title="Analyse des menaces", icon=":material/psychology:"),
    st.Page("views/misp.py", title="Gestion MISP", icon=":material/hub:"),
    st.Page("views/blockchain.py", title="Validation blockchain", icon=":material/token:"),
    st.Page("views/reliability.py", title="Fiabilité & réputation", icon=":material/verified:"),
    st.Page("views/correlation.py", title="Corrélation", icon=":material/share:"),
    st.Page("views/documentation.py", title="Documentation", icon=":material/menu_book:"),
]
st.navigation(pages).run()
