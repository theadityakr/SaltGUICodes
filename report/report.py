import json
import os
import openpyxl
import pandas as pd
def merge_json_files(output_file, input_folder):
    merged_data = []
    for filename in os.listdir(input_folder):
        #print(filename)
        if filename.endswith(".json"):
            file_path = os.path.join(input_folder, filename)
            with open(file_path, 'r',encoding="utf-16") as file:
                try:
                    data = json.load(file)
                except UnicodeError as e:
                    print(f"Error decoding the file: {e}")
                merged_data.append(data)
    with open(output_file, 'w') as output_file:
        json.dump(merged_data, output_file, indent=2)

def json_to_excel(input_folder,output_file):
    with open(input_folder, 'r') as file:
        try:
            data = json.load(file)
            df = pd.DataFrame(data)
            df.to_excel(output_file,index=False)
        except UnicodeError as e:
            print(f"Error decoding the file: {e}")


def json_to_excel_aspose():
    import  jpyp
    import  asposecells
    jpype.startJVM()
    from asposecells.api import Workbook
    workbook = Workbook("report.json")
    workbook.save("report.xlsx")
    jpype.shutdownJVM()


def mail_report():
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.application import MIMEApplication
    from datetime import datetime

    # Set your Gmail credentials
    gmail_user = 'apps.salt.project@gmail.com'
    gmail_password = 'cujz ftok bxkb kbbh'

    # Set the recipient email address
    to_email = 'theaditykr@gmail.com'

    # Create the email message
    subject = 'Salt Asset Management Report'
    current_date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f'Report from Salt Project.\n\nCurrent Date and Time: {current_date_time}'
    message = MIMEMultipart()
    message['From'] = gmail_user
    message['To'] = to_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    # Attach a file (replace 'your_file_path.pdf' with the actual path to your file)
    file_path = '/srv/salt/report/report.xlsx'
    attachment = open(file_path, 'rb')
    part = MIMEApplication(attachment.read(), Name='report.xlsx')
    attachment.close()
    part['Content-Disposition'] = f'attachment; filename={part["Name"]}'
    message.attach(part)

    # Connect to Gmail SMTP server
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_password)
        server.sendmail(gmail_user, to_email, message.as_string())
        #print('Email with attachment sent successfully!')
    except Exception as e:
        print(f'Error: {str(e)}')
    finally:
        server.quit()


if __name__ == "__main__":

    input_folder = '/srv/salt/report/salt'
    output_file = '/srv/salt/report/report.json'
    merge_json_files(output_file, input_folder)
    json_to_excel(output_file,'/srv/salt/report/report.xlsx')
    mail_report()

    #with open(output_file, 'r') as file:
        #data = json.load(file)
    #df = pd.io.json.json_normalize(data)
    #df.to_excel('/srv/salt/report/report.xlsx')

