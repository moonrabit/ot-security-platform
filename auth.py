"""
Simple authentication module using Streamlit secrets.
Credentials are stored as SHA-256 hashes in .streamlit/secrets.toml
"""
import hashlib
import streamlit as st


def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _load_credentials() -> dict[str, str]:
    try:
        return dict(st.secrets["credentials"])
    except Exception:
        # Fallback if secrets not configured — blocks all access
        return {}


def login_wall() -> None:
    """
    Renders the login form and blocks execution if not authenticated.
    Call this at the top of app.py before any other content.
    """
    if st.session_state.get("authenticated"):
        return

    # Center the login form
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("## OT Security Platform")
        st.markdown("---")

        with st.form("login_form", clear_on_submit=False):
            st.markdown("**Iniciar sesión**")
            username = st.text_input("Usuario", placeholder="usuario")
            password = st.text_input("Contraseña", type="password", placeholder="••••••••")
            submitted = st.form_submit_button("Ingresar", use_container_width=True, type="primary")

        if submitted:
            credentials = _load_credentials()
            if not credentials:
                st.error("No hay credenciales configuradas en secrets.toml")
            elif username in credentials and credentials[username] == _hash(password):
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.rerun()
            else:
                st.error("Usuario o contraseña incorrectos.")

        st.caption("Acceso restringido · OT Security Assessment Platform")

    st.stop()


def require_auth() -> None:
    """
    Call at the top of every page to redirect unauthenticated users.
    Lighter than login_wall — just blocks and shows a message.
    """
    if not st.session_state.get("authenticated"):
        st.warning("Debés iniciar sesión primero.")
        st.page_link("app.py", label="← Ir al login")
        st.stop()


def logout() -> None:
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    st.rerun()


def current_user() -> str:
    return st.session_state.get("username", "")
