import streamlit as st
from function import FeatureExtraction, predict
import time

# Add CSS styles
def local_css(file_path):
    with open(file_path) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def main():
    local_css("styles.css")
    st.title('Phishing Website Detector')

    url = st.text_input('Enter the URL:')
    result = ""

    if st.button('Predict'):
        with st.spinner('Predicting...'):
            result = predict(url)
            time.sleep(2)

        if result == -1:
            st.error('The website is predicted to be a phishing website!')
        elif result == 1:
            st.success('The website is predicted to be legitimate!')
        else:
            st.warning('Something went wrong, unable to predict!')

if __name__ == '__main__':
    main()

