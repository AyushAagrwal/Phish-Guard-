import streamlit as st
from function import FeatureExtraction, predict
import time
import validators

st.set_page_config(
    page_title="PhishGuard",
    page_icon="./img/logo.ico",
    # layout="wide",
    initial_sidebar_state="collapsed",
)

# Add CSS styles
def local_css(file_path):
    with open(file_path) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def main():
    local_css("styles.css")
    st.title('Phishing Website Detector')

    url = st.text_input('Enter the URL:').strip()
    result = ""

    if url:  # Check if the user has entered something in the input field
        if validators.url(url):  # Check if the entered URL is valid
            if st.button('Predict'):
                with st.spinner('Predicting...'):
                    result = predict(url)
                    time.sleep(2)

                if result == -1:
                    st.error('The website is predicted to be a phishing website.')
                    st.markdown('<div role="alert" data-type="unsafe">The website is predicted to be a phishing website.</div>', unsafe_allow_html=True)
                elif result == 1:
                    st.success('The website is predicted to be legitimate.')
                    st.markdown('<div role="alert" data-type="safe">The website is predicted to be legitimate.</div>', unsafe_allow_html=True)
                else:
                    st.warning('Something went wrong, unable to predict.')
        else:
            st.error('Please enter a valid URL.')
            st.markdown('<div role="alert" data-type="invalid">Please enter a valid URL.</div>', unsafe_allow_html=True)
    else:
        st.warning('Please enter a URL.')

if __name__ == '__main__':
    main()
