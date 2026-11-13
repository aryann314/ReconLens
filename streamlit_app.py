import streamlit as st

st.set_page_config(page_title="ReconLens", layout="wide")

st.title("ReconLens")
st.subheader("OSINT-Based Digital Footprint Analysis")

target = st.text_input("Enter a domain, username, email, or IP")

if st.button("Start Investigation"):
    if target:
        st.info("Connect this interface to the existing ReconLens scanning logic.")
    else:
        st.warning("Please enter a target.")
