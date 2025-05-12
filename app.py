import streamlit as st
import pandas as pd
import joblib
import requests
import os
import math
import secrets
import string
from streamlit_extras.colored_header import colored_header  # For the gradient headers
from streamlit_extras.add_vertical_space import add_vertical_space #for adding space
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
        strength_color = "red"
    elif predicted_strength < 0.4:
        strength_assessment = "Weak"
        strength_color = "orange"
    elif predicted_strength < 0.6:
        strength_assessment = "Medium"
        strength_color = "yellow"
    elif predicted_strength < 0.8:
        strength_assessment = "Strong"
        strength_color = "green"
    else:
        strength_assessment = "Very Strong"
        strength_color = "darkgreen"  # More distinct for very strong

    predicted_crack_time_category = model_crack_time.predict(input_data)[0]

    return {
        'strength': predicted_strength,
        'strength_percentage': f"{predicted_strength_percentage:.2f}%",
        'strength_assessment': strength_assessment,
        'strength_color': strength_color, #added color
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
st.set_page_config(page_title="Password Security Checker", page_icon="🔒") #Added a page config
st.title("Password Security Checker & Generator")
add_vertical_space(1) #added some space

# --- Load Models ---
STRENGTH_MODEL_URL = "YOUR_PUBLIC_URL_TO_model_strength_rf.joblib"  # Replace this!
CRACK_TIME_MODEL_URL = "YOUR_PUBLIC_URL_TO_model_crack_time_clf.joblib"  # Replace this!
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
colored_header(
    label="Check Password Strength",
    description="Enter your password to analyze its security.",
    color_name="blue-60",
)
password_input = st.text_input("Enter your password:", "", type="password") #Added type password

if password_input and model_strength_rf and model_crack_time_clf:
    prediction = predict_password_security(password_input, model_strength_rf, model_crack_time_clf)
    st.subheader("Analysis Results:")
    # Using markdown for colored strength assessment and applying color to the metric
    st.markdown(
        f"<span style='font-size: 20px; color: {prediction['strength_color']};'>{prediction['strength_assessment']}</span>",
        unsafe_allow_html=True,
    )
    st.metric("Strength", prediction['strength_percentage'])
    st.write(f"**Estimated Crack Time:** {prediction['crack_time_category']}")

# --- Random Password Generator Section ---
colored_header(
    label="Generate Secure Password",
    description="Customize and generate strong passwords.",
    color_name="green-60",
)
col1, col2 = st.columns(2)
with col1:
    password_length = st.slider("Password Length:", min_value=8, max_value=32, value=16)
with col2:
    num_passwords = st.number_input("Number of Passwords to Generate:", min_value=1, max_value=5, value=1, step=1)

use_uppercase = st.checkbox("Include Uppercase", True)
use_lowercase = st.checkbox("Include Lowercase", True)
use_digits = st.checkbox("Include Digits", True)
use_symbols = st.checkbox("Include Symbols", True)

if st.button("Generate Password(s)", use_container_width=True): #made button wider
    for i in range(num_passwords):
        random_password = generate_random_password(password_length, use_uppercase, use_lowercase, use_digits, use_symbols)
        st.success(f"Generated Password {i+1}: {random_password}") # used success

st.markdown("---")
st.markdown("A user-friendly tool for checking password security and generating strong, random passwords.")
