import pandas as pd
import re
import os

# Ask user for input file name (default name provided)
file_name = input("Enter the name of your CSV file (including .csv): ").strip()

# Define file path dynamically (assumes script is in the same folder as the CSV)
file_path = os.path.join(os.getcwd(), file_name)

# Check if file exists before proceeding
if not os.path.isfile(file_path):
    print(f"Error: File '{file_name}' not found in {os.getcwd()}. Please check the file name and try again.")
    exit()

# Read the CSV file into a DataFrame
data = pd.read_csv(file_path)

# Function to sanitize IP addresses
def sanitize_ip(ip):
    if isinstance(ip, str) and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        return re.sub(r'(\d+\.\d+\.\d+)\.\d+$', r'\1.xxx', ip)
    return ip  # If not a valid IP, return as is

# Ask the user for the correct column name containing IP addresses
print("Available columns:", list(data.columns))
ip_column_name = input("Enter the column name containing IP addresses: ").strip()

# Check if the column exists
if ip_column_name in data.columns:
    data[ip_column_name] = data[ip_column_name].apply(sanitize_ip)
else:
    print(f"Error: Column '{ip_column_name}' not found in CSV. Please check column names!")
    exit()

# Save sanitized data
output_file = "sanitized_log_file.csv"
data.to_csv(output_file, index=False)

print(f"Sanitized file saved to {output_file} in {os.getcwd()}")