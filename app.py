from gevent import monkey
monkey.patch_all()
from flask import Flask,render_template, request,jsonify
import joblib
import os
import pandas as pd
import numpy as np
import sklearn
import imblearn
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split,cross_val_score,RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LinearRegression,LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score,recall_score,f1_score,confusion_matrix,classification_report
from imblearn.over_sampling import SMOTE
from scipy.stats import randint
import tldextract as tld
import re
from urllib.parse import urlparse
import requests
from time import time
import time
from ipwhois import IPWhois
import whois
import socket
from datetime import datetime
from collections.abc import Iterable
import dns.resolver
import os
from db import session  # Import the session from db.py
import uuid

feature_names=['qty_slash_url', 'length_url', 'qty_dot_domain', 'qty_vowels_domain',
       'domain_length', 'qty_dot_directory', 'qty_underline_directory',
       'qty_slash_directory', 'qty_equal_directory', 'qty_at_directory',
       'qty_and_directory', 'qty_exclamation_directory', 'qty_tilde_directory',
       'qty_comma_directory', 'qty_asterisk_directory', 'qty_dollar_directory',
       'qty_percent_directory', 'directory_length', 'qty_dot_file',
       'qty_slash_file', 'qty_questionmark_file', 'qty_equal_file',
       'qty_at_file', 'qty_space_file', 'qty_comma_file', 'qty_plus_file',
       'qty_asterisk_file', 'file_length', 'time_response', 'asn_ip',
       'time_domain_activation', 'time_domain_expiration', 'qty_nameservers',
       'qty_mx_servers', 'ttl_hostname']


model = joblib.load('models/model.pkl')


def insert_data(url,is_phishing):

    is_phishing =is_phishing

    # Insert into Astra DB
    query = "INSERT INTO phishing_data (id, url, prediction, created_at) VALUES (%s, %s, %s, %s)"
    session.execute(query, (uuid.uuid4(), url, is_phishing, datetime.utcnow()))
    

def find_features(url):
    input_features=[]
    # URL features
    url_slashes=url.count("/")
    url_length=len(url)
    extractor = tld.TLDExtract(
        suffix_list_urls=[
            "https://publicsuffix.org/list/public_suffix_list.dat",
            "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"
        ]
    )
    # Use the extractor to extract the URL components
    extracted_url = extractor(url)
    domain=extracted_url.domain
    domain_dots=domain.count(".")
    vowels=len(re.findall(r"[aeiouAEIOU]",domain))
    domain_length=len(domain)
    
    input_features.extend([url_slashes,url_length,domain_dots,vowels,domain_length])
    
    #Directory Features
    parsed_url=urlparse(url)
    path=parsed_url.path
    directory = '/'.join(path.strip('/').split('/')[:-1]) #in case of removing the last file name from the path
    directory="/"+directory
    path_symbols_list=[".","_","/","=","@","&","!","~",",","*","$","%"]
    
    for symbol in path_symbols_list:
        length=directory.count(symbol)
        input_features.append(length)
    
    
    path_length=len(directory)
    input_features.append(path_length)
    
    #File based features
    file_symbol_list= [".","/","?","=","@","%20",",","+","*"]
    file_name=path.split("/")[-1]
    
    for symbol in file_symbol_list:
        count=file_name.count(symbol)
        input_features.append(count)
    
    file_name_length=len(file_name)
    input_features.append(file_name_length)
    
    #response time features
    start_time=time.time()
    end_time=time.time()
    
    try:
        response = requests.get(url, timeout=10)
        response_time = end_time - start_time
    except requests.exceptions.RequestException:
        response_time = -1  # Default if request fails
    input_features.append(response_time)
    
    #Network and domain features
    ip_address=socket.gethostbyname(parsed_url.netloc)
    ipwhois=IPWhois(ip_address)
    asn=ipwhois.lookup_whois()["asn"]
    input_features.append(int(asn))
    
    domain_name = whois.whois(url)
    start_date=domain_name['creation_date']
    end_date=domain_name['expiration_date']
    if isinstance(start_date,Iterable):
        start_date=start_date[0] if start_date else None
        
    if isinstance(end_date,Iterable):
        end_date=end_date[0] if end_date else None
     
    today=datetime.today()
       
    if start_date is None:
        creation_date=-1
    else:
        creation_date=(today-start_date).days
        
    if end_date is None:
        expiration_date=-1
    else:
        expiration_date=(end_date-today).days

    # creation_date=int(str(days).split()[0])
    # expiration_date=int(str(days_left).split()[0])
    input_features.extend([creation_date,expiration_date])
    nameservers=domain_name.name_servers
    
    if nameservers is None:
        nameservers=0
    else:
        nameservers=len(domain_name.name_servers)
    input_features.append(nameservers)
    
    parsed_url=parsed_url.netloc
    parsed_domain=parsed_url.replace("www.","")
    
    try:
        mx_records=dns.resolver.resolve(parsed_domain,"MX")
    
    except dns.resolver.NoAnswer:
        mx_records=""
    
    input_features.append(len(mx_records))
    
    try:
        ttl_records = dns.resolver.resolve(parsed_url, "A")
        ttl_value = ttl_records.ttl
    except:
        ttl_value = -1  # Default if lookup fails
    input_features.append(ttl_value)

    return input_features
    
app=Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan_URL",methods=['POST'])
def scan():
    url = request.form.get("URL")
    time.sleep(2)
    
    if not (url.startswith("https://") or url.startswith("http://")):
        url = "https://" + url
        
    features=find_features(url)
    features=np.array(features).reshape(1, -1) # Shape: (1, n_features)
    features_df=pd.DataFrame(features,columns=feature_names)
    preds=model.predict(features_df)
    if preds[0]==0:
        is_phishing="False"
        insert_data(url,is_phishing)
        return jsonify({"phishing":False,"message":"Don't worry, This link is safe"})
    else:
        is_phishing="True"
        insert_data(url,is_phishing)
        with open("phishing mails.txt","a") as file:
            file.write(url)
        return jsonify({"phishing":True,"message":"Beware! The URL looks suspicious"})

    
if __name__=="__main__":
    app.run( host='0.0.0.0', port = int(os.environ.get("PORT", 5000)))

    

