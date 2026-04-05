import os
import pickle
import random

import requests

# Bad: Hardcoded API Key
api_key = "sk-proj-1234567890abcdef"


# Bad: Unencrypted HTTP request
def get_patient_data(patient_id):
    url = f"http://api.hospital-system.com/patient/{patient_id}"
    response = requests.get(url)
    return response.json()


# Bad: Insecure Deserialization
def load_patient_record(data):
    return pickle.loads(data)


# Bad: Weak Randomness for Session Token
def generate_session_token():
    return str(random.random())


# Bad: SQL Injection
def search_patients(name):
    query = "SELECT * FROM patients WHERE name = '%s'" % name
    # cursor.execute(query) # Simulated
