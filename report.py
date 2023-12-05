import json
import os


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

if __name__ == "__main__":

    input_folder = '/srv/salt/report/salt'
    output_file = '/srv/salt/report/report.json'
    #merge_json_files(output_file, input_folder)

