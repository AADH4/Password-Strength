import streamlit as st
import pandas as pd
import joblib
import requests
import os
import math
import re
import numpy as np
import secrets
import string

# --- Define your entropy calculation function ---
def calculate_entropy(password):
    if not password:
        return 0
    entropy = 0
    alphabet = {}
    for char in password:
        alphabet[char] = alphabet.get(char, 0) + 1
    for count in alphabet.values():
        probability = count / len(password)
        entropy -= probability * math.log2(probability)
    return entropy

# --- Define the prediction function ---
def predict_password_security(password, model_strength, model_crack_time):
    password_length = len(password)
    uppercase_count = sum(1 for c in password if c.isupper())
    lowercase_count = sum(1 for c in password if c.islower())
    digit_count = sum(1 for c in password if c.isdigit())
    symbol_count = sum(1 for c in password if not c.isalnum())
    entropy_calculated = calculate_entropy(password)

    input_data = pd.DataFrame({
        'password_length': [password_length],
        'uppercase_count': [uppercase_count],
        'lowercase_count': [lowercase_count],
        'digit_count': [digit_count],
        'symbol_count': [symbol_count],
        'entropy_calculated': [entropy_calculated],
        'entropy': [calculate_entropy(password)]
    })

    predicted_strength = model_strength.predict(input_data)[0]
    predicted_strength_percentage = predicted_strength * 100

    if predicted_strength < 0.2:
        strength_assessment = "Very Weak"
    elif predicted_strength < 0.4:
        strength_assessment = "Weak"
    elif predicted_strength < 0.6:
        strength_assessment = "Medium"
    elif predicted_strength < 0.8:
        strength_assessment = "Strong"
    else:
        strength_assessment = "Very Strong"

    predicted_crack_time_category = model_crack_time.predict(input_data)[0]

    return {
        'strength': predicted_strength,
        'strength_percentage': f"{predicted_strength_percentage:.2f}%",
        'strength_assessment': strength_assessment,
        'crack_time_category': predicted_crack_time_category
    }

# --- Define the random password generator ---
def generate_random_password(length=12, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
    characters = ''
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return "Please select at least one character type."

    return ''.join(secrets.choice(characters) for _ in range(length))

# --- Streamlit App ---
st.title("Password Security Checker & Generator")

# --- Load Models ---
STRENGTH_MODEL_URL = "https://drive.google.com/uc?id=1A1hZ0hylMhwhg_suKAj4UxaV9-CDME3Z&export=download"
CRACK_TIME_MODEL_URL = "https://drive.google.com/uc?id=1v9OnTOnG9SQ7xQZO1RfrKJ_lgj13hCWM&export=download"
STRENGTH_MODEL_PATH = "model_strength_rf.joblib"
CRACK_TIME_MODEL_PATH = "model_crack_time_clf.joblib"

@st.cache_resource
def load_models():
    if not os.path.exists(STRENGTH_MODEL_PATH):
        st.info("Downloading strength model...")
        try:
            response = requests.get(STRENGTH_MODEL_URL)
            response.raise_for_status()
            with open(STRENGTH_MODEL_PATH, 'wb') as f:
                f.write(response.content)
            st.success("Strength model downloaded!")
        except requests.exceptions.RequestException as e:
            st.error(f"Error downloading strength model: {e}")
            return None, None

    if not os.path.exists(CRACK_TIME_MODEL_PATH):
        st.info("Downloading crack time model...")
        try:
            response = requests.get(CRACK_TIME_MODEL_URL)
            response.raise_for_status()
            with open(CRACK_TIME_MODEL_PATH, 'wb') as f:
                f.write(response.content)
            st.success("Crack time model downloaded!")
        except requests.exceptions.RequestException as e:
            st.error(f"Error downloading crack time model: {e}")
            return None, None

    try:
        strength_model = joblib.load(STRENGTH_MODEL_PATH)
        crack_time_model = joblib.load(CRACK_TIME_MODEL_PATH)
        return strength_model, crack_time_model
    except Exception as e:
        st.error(f"Error loading models: {e}")
        return None, None

model_strength_rf, model_crack_time_clf = load_models()

# --- Password Checker Section ---
st.subheader("Check Password Strength")
password_input = st.text_input("Enter your password to analyze:", "")

if password_input and model_strength_rf and model_crack_time_clf:
    prediction = predict_password_security(password_input, model_strength_rf, model_crack_time_clf)
    st.subheader("Analysis Results:")
    st.metric("Strength", f"{prediction['strength_percentage']}", f"({prediction['strength_assessment']})")
    st.write(f"**Estimated Crack Time:** {prediction['crack_time_category']}")

# --- Random Password Generator Section ---
st.subheader("Generate Secure Password")
col1, col2 = st.columns(2)
with col1:
    password_length = st.slider("Password Length:", min_value=8, max_value=32, value=16)
with col2:
    num_passwords = st.number_input("Number of Passwords to Generate:", min_value=1, max_value=5, value=1, step=1)

use_uppercase = st.checkbox("Include Uppercase Letters", True)
use_lowercase = st.checkbox("Include Lowercase Letters", True)
use_digits = st.checkbox("Include Digits", True)
use_symbols = st.checkbox("Include Symbols", True)

if st.button("Generate Password(s)"):
    for i in range(num_passwords):
        random_password = generate_random_password(password_length, use_uppercase, use_lowercase, use_digits, use_symbols)
        st.write(f"**Generated Password {i+1}:** `{random_password}`")

st.markdown("---")
st.markdown("A simple password security checker and generator.")
