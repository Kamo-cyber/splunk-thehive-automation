import logging
import requests
import os

logging.basicConfig(level=logging.INFO)

def virustotal_enrichment(ip_address, virus_total_key, virus_total_url):

    try:
        headers = {"x-apikey": virus_total_key}

        response = requests.get(virus_total_url, headers=headers, timeout=10)

    except Exception as error:
        logging.error(f"Error occured during requests: {error}")
        logging.info(response.status_code)

    else:
        logging.info("Outbound request successful and complete!")
        parsed_response = response.json()
        
        dictionary = {}
        dictionary["country"] = parsed_response.get("data").get("attributes").get("country")
        dictionary["malicious_count"] = parsed_response.get("data").get("attributes").get("last_analysis_stats").get("malicious")
        dictionary["reputation"] = parsed_response.get("data").get("attributes").get("reputation")
        dictionary["Owner"] = parsed_response.get("data").get("attributes").get("as_owner")
        
        return dictionary

def mxtoolbox_enricher(ip_address, mxtoolbox_key, mxtoolbox_url):
    try:
       
        headers = {
            "Authorization": mxtoolbox_key
        }

        params = {
            "argument": ip_address
        }

        response = requests.get(mxtoolbox_url, headers=headers, params=params)

    except Exception as error:
        logging.error(f"Error occured during requests lookup: {error}")
        logging.error(response.status_code)

    else:
            mx_dictionary = {}
            logging.info("Successful blacklist lookup!")
            parsed_response = response.json()
            check = isinstance(parsed_response, dict)

            if check == False:
                logging.error(parsed_response)
                return None

            else:
                Failed = parsed_response.get("Failed")

                mx_dictionary["Count"] = len(Failed)
                mx_dictionary["Name"] = []

                for item in Failed:
                
                    mx_dictionary["Name"].append(item.get("Name"))

                return mx_dictionary

            
if "__main__" == __name__:
    ip_address = "192.169.2.50"
    key = os.environ.get("vtkey")
 
    virustotal_enrichment(ip_address, key, f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}")