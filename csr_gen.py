import argparse
import re
from PyPDF2 import PdfReader
import pyperclip

# Initialize the ArgumentParser object
parser = argparse.ArgumentParser(description="Generate .conf file from PDF form.")
parser.add_argument("pdf_file_path", help="Path to the PDF file containing form data.")
args = parser.parse_args()
pdf_file_path = args.pdf_file_path

# Function to extract filled-in form fields using PyPDF2
def extract_pdf_form_fields(pdf_file_path):
    with open(pdf_file_path, "rb") as f:
        pdf_reader = PdfReader(f)
        form_fields = pdf_reader.get_form_text_fields()
    return form_fields

# Extract form fields from the PDF
pdf_form_fields = extract_pdf_form_fields(pdf_file_path)

# Define the .conf template with corrected formatting
conf_template = """[ req ]
distinguished_name  = req_distinguished_name
req_extensions      = req_ext

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
									# US
countryName_default             = {Country}
stateOrProvinceName             = State or Province Name (full name)
									# Indiana
stateOrProvinceName_default     = {State}
localityName                    = Locality Name (eg, city)
									# Indianapolis
localityName_default            = {Location}
organizationName                = Organization Name (eg, company)
									# Foo Group, Inc.
organizationName_default        = {Organization}
organizationalUnitName          = Organization Unit (eg, department)
									# Information Technology
organizationalUnitName_default  = {Org_Unit}
emailAddress                    = Email Address (eg, webmaster@example.com)
									# foo.guy@bar.com
emailAddress_default            = {Email}
commonName                      = 	Common Name (eg, YOUR name)
commonName_max                  = 64
									# *.foo.com
commonName_default              = {CN}

[ req_ext ]
subjectAltName          = @alt_names

[alt_names ]
[alt_names ]
{alt_names_list}
"""

# Get the CNs from the form and split them based on possible delimiters (',', ';', '\\r')
cn_field = pdf_form_fields.get('Your Valid domain name', 'Unknown')
cn_values = re.split(';|,|\\\\r|\\n|\\s', cn_field)

# Sanitize each CN value by removing 'https://' and any trailing '/'
cn_values = [re.sub(r'^https?://', '', cn).rstrip('/') for cn in cn_values]

# Trim any leading/trailing whitespace from each CN and filter out empty or whitespace-only strings
cn_values = [cn.strip().lower() for cn in cn_values if cn.strip()]

# Check for wildcard domains and add the root domain
for cn in cn_values:
    if cn.startswith('*.'):
        root_domain = cn[2:]
        if root_domain not in cn_values:
            cn_values.append(root_domain)


# Prepare the alt_names list with all the CN values
alt_names_list = "\n".join([f'DNS.{i+1} = {cn}' for i, cn in enumerate(cn_values)])

# Choose the first CN as the commonName
first_cn = cn_values[0]

# Map the extracted form fields to the .conf template placeholders
mapping = {
    'Country': pdf_form_fields.get('Your Valid Country Name (2 letter code)', 'Unknown'),
    'State': pdf_form_fields.get('Your Valid State or Province Name spelled out', 'Unknown'),
    'Location': pdf_form_fields.get('Your Valid City Name (spelled out)', 'Unknown'),
    'Organization': pdf_form_fields.get('Your Valid Organization (Corporation) Name', 'Unknown'),
    'Org_Unit': pdf_form_fields.get('Your Valid Department Name (optional)', 'Unknown'),
    'Email': pdf_form_fields.get('Your Valid Email Address', 'Unknown'),
    'CN': first_cn,
    'alt_names_list': alt_names_list
}

# Populate the .conf template
filled_conf = conf_template.format(**mapping)

# Copy to clipboard
pyperclip.copy(filled_conf)

# Print the filled .conf template
print(filled_conf)

# Print that the .conf template has been copied to the clipboard
print("\n.conf template copied to clipboard.")
