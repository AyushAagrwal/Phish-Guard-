import streamlit as st
from functions import FeatureExtraction, predict

def main():
    st.title('Phishing Website Detector')

    url = st.text_input('Enter the URL:')
    result = ""

    if st.button('Predict'):
        with st.spinner('Predicting...'):
            result = predict(url)
            st.write(result)

if __name__ == '__main__':
    main()
