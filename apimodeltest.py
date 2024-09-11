import re
import requests
import json
import urllib3
from datetime import datetime
from azure.core.credentials import AzureKeyCredential
from azure.ai.formrecognizer import DocumentAnalysisClient
import os
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def process_file(recordid,base64_string,output_file_path):
    base64_to_file(base64_string, output_file_path)
    # Decodificar la cadena base64 a binario
    file_path = output_file_path
    
    # Load the model
    endpoint = "https://testforintegration.cognitiveservices.azure.com/"
    key = "5c1e31c6c51f4abc9e23c760602f9f54"
    model_id = "LOP_Model_CU"
    model = load_model(endpoint, key)

    # Process and extract data from the downloaded PDF
    field_names = ["onb_street", "onb_zip", "onb_city", "onb_state", "onb_claim_number", "onb_mail", "onb_policy_number", "onb_date_of_loss", "oab_date", "lop_date", "onb_street2", "lop_signed_by_hoh"]
    result = process_data(model, model_id, file_path)
    extracted_data = extract_data(result, field_names)

    # Get the token for API request
    login_url = "https://pdss.eastus.cloudapp.azure.com/webservice/Users/Login"
    token = consume_get_token(login_url, headers={
        "X-ENCRYPTED": "0",
        "x-api-key": "z2WYcMmWT8PTNT36mervcMBhc65bQ2Jy",
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic U2FuZGJveDpGaldKTnhuOFRiS3oyTXo0YVJGUXZuZjhBcFBMdWc3Mg=="
    })

    if token:
        # Send the PUT request with the extracted data
        put_url = f"https://pdss.eastus.cloudapp.azure.com/webservice/Claims/Record/{recordid}"
        response = consume_put_api(put_url, token, extracted_data)
        if response:
            print("PUT request response:", response)
        else:
            print("PUT request failed.")
    else:
        print("Failed to obtain token.")

#create a function for convert base64 file to pdf (receive by API ) 
def file_to_base64(file_path):
    # Abrir el archivo en modo binario
    with open(file_path, "rb") as file:
        # Leer el contenido del archivo y convertirlo a base64
        encoded_string = base64.b64encode(file.read()).decode('utf-8')
    return encoded_string

def base64_to_file(base64_string, output_file_path):
    # Decodificar la cadena base64 a binario
    with open(output_file_path, "wb") as file:
        file.write(base64.b64decode(base64_string))

def load_model(endpoint, key):
    document_analysis_client = DocumentAnalysisClient(endpoint=endpoint, credential=AzureKeyCredential(key))
    return document_analysis_client

def process_data(model, model_id, document_path):
    try:
        with open(document_path, "rb") as f:
            poller = model.begin_analyze_document(model_id=model_id, document=f)
            result = poller.result()
            return result
        
    except Exception as e:
        print(f"Error processing data: {e}")
        return None

def extract_data(result, field_names):
    field_dict = {field: "" for field in field_names}
    for document in result.documents:
        for name, field in document.fields.items():
            field_value = field.value if field.value else field.content

            if "date" in  name and field_value is not None:
                field_value = field_value.replace("/", "-")
                               
            if name in field_dict:
                field_dict[name] = field_value if field_value is not None else ""
    print("Field Dict:", field_dict)
    return field_dict
    
def authenticate_google_drive(removed):  # Removed as not used in this version
    pass

def consume_get_token(url, headers=None):
    try:
        data = {
            "userName": "Sandbox",
            "password": "SandboxAPI2023!Aug"
        }
        response = requests.post(url, headers=headers, data=data, verify=False)
        if response.status_code == 200:
            response_data = response.json()
            token = response_data.get('result', {}).get('token')
            if token:
                return token
            else:
                print("Token not found in response.")
                return None
        else:
            print(f"Error: Login request failed with status code {response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def consume_put_api(url, token, data):
    try:
        headers = {
            "x-api-key": "z2WYcMmWT8PTNT36mervcMBhc65bQ2Jy",
            "x-token": token,
            "Content-Type": "application/json",
            "Authorization": "Basic U2FuZGJveDpGaldKTnhuOFRiS3oyTXo0YVJGUXZuZjhBcFBMdWc3Mg=="
        }
        response = requests.put(url, headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            print("PUT request successful!")
            return response.json()
        else:
            print(f"Error: PUT request failed with status code {response.status_code}")
            return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def main():
    # User Input for File Path
    file_path = input("Enter the path to the PDF document: ")

    recordid="379703"
    base64string = file_to_base64(file_path)
    output_file_path_temp = "{}.pdf".format(datetime.now().strftime("%Y%m%d_%H%M%S"))
    process_file(recordid, base64string, output_file_path_temp)
    os.remove(output_file_path_temp)

if __name__ == "__main__":
    main()
    print("Process completed.")