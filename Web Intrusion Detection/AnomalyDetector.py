## The main deployment file
import pandas as pd 
import re
import os
import pickle
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from alert import mainalert

def feature(df):

    # Extract unique connections based on IP address and request
    uc = df[['ip', 'request']].drop_duplicates()
    # Count the number of unique connections for each IP address
    uc_count = uc['ip'].value_counts()
    # Volume by IP address
    ip_volume = df.groupby('ip')['size'].sum()

    # Add the new feature to the original DataFrame
    df['ip_frequency'] = df['ip'].map(uc_count)
    df['unique_connections_count'] = df['ip'].map(uc_count)
    df['ip_volume'] = df['ip'].map(ip_volume)


    # Add a feature to identify URL string aberrations
    def detect_aberrations(url):
        if re.search(r'/\./|/\.\./', url):
            return 1  # Indicates the presence of aberrations
        else:
            return 0  # Indicates no aberrations

    df['url_aberrations'] = df['request'].apply(detect_aberrations)

    ## Add feature
    ##  identify unusual referrer patterns. 

    unusual_referrer_pattern = re.compile(r'^-|^(https?://[^/]+)?example\.com')

    # Add a feature to identify unusual referrer patterns
    def detect_unusual_referrer(referrer):
        if unusual_referrer_pattern.match(referrer):
            return 0  # Indicates a usual referrer pattern
        else:
            return 1  # Indicates an unusual referrer pattern

    df['unusual_referrer'] = df['referer'].fillna('').apply(detect_unusual_referrer)


    def user_agent_analysis(user_agent):
    
    # Here, we simply check if the User-Agent string contains "Mosaic/0.9" or if it's a never-before-seen User-Agent
        if 'Mosaic/0.9' in user_agent:
            return 'old_client'  # Indicates an extremely old client
        elif user_agent not in known_user_agents:
            return 'unusual_user_agent'  # Indicates a never-before-seen User-Agent
        else:
            return 'normal'  # Indicates a normal User-Agent

    # Perform frequency analysis to identify known User-Agent strings
    known_user_agents = df['user_agent'].value_counts().index.tolist()

    # Apply the user_agent_analysis function to create a new feature
    df['user_agent_analysis'] = df['user_agent'].apply(user_agent_analysis)



    def detect_out_of_order_access(ip_address, request):
      
        if ip_address in endpoint_sequence and request != endpoint_sequence[ip_address]:
            return 1  # Indicates out-of-order access
        else:
            endpoint_sequence[ip_address] = request
            return 0  # Indicates normal access

    # Initialize a dictionary to store the expected sequence of accesses for each IP address
    endpoint_sequence = {}

    # Apply the detect_out_of_order_access function to create a new feature
    df['out_of_order_access'] = df.apply(lambda row: detect_out_of_order_access(row['ip'], row['request']), axis=1)
    

    X=df.drop(columns=['ip','request','time','size','referer','user_agent'],axis=1)

    X['user_agent_analysis'] = df['user_agent_analysis'].astype('category').cat.codes  # Convert categorical to numerical

    
    return X


def preprocess(log_file):

    ### Convert to a Data Frame
    df = pd.read_csv(log_file,sep=r'\s(?=(?:[^"]*"[^"]*")*[^"]*$)(?![^\[]*\])',engine='python',
                usecols=[0, 3, 4, 5, 6, 7, 8],
                names=['ip', 'time', 'request', 'status', 'size', 'referer', 'user_agent'],
                na_values='-',header=None)

    # Remove missing values
    df.dropna(inplace=True)
    X = feature(df)

    return X


def main():

    folder = '/app/data2'
    while True:
    # Filter for CSV files that haven't been processed yet
        for new_file in os.listdir(folder):
            if new_file == 'access.log':
                file_path = os.path.join(folder, new_file)
                print(f"Detected new CSV file: {file_path}")
                X = preprocess(file_path)
                uc = X['unique_connections_count'].nunique()
                
                # Load the model
                with open('isolationforestv2.pkl', 'rb') as model_file:
                    model = pickle.load(model_file)

                # Load the scaler
                with open('scalerv2.pkl', 'rb') as scaler_file:
                    scaler = pickle.load(scaler_file)
    
                new = scaler.transform(X)
                pred = model.predict(new)
                X['Anomaly'] = pred
               
                # Calculate the number of anomalies
                anomalies_count = X[X['Anomaly'] == -1].shape[0]
                # Set the threshold for triggering an alert (25% of unique connections)
                alert_threshold = 0.2 * uc
                mainalert(anomalies_count,alert_threshold,uc)
                            
                X.to_csv('/app/data2/results',index=False)
                os.remove(file_path)

main()


