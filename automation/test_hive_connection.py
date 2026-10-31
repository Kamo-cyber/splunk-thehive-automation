import requests 
import logging
import os
import time
from email_security_and_threat_intelligence_enrichment import virustotal_enrichment
from threat_syncer import build_mitre_layer, export_attack_json
logging.basicConfig(level=logging.INFO)

def fetch_splunk_alerts(splunk_url, auth, search_data):

    try:

        response_splunk = requests.post(splunk_url, auth=auth, data=search_data, timeout=15, verify=False)
        parameters = {"output_mode": "json"}
        sid = response_splunk.json()["sid"]

        status_check_url = f"https://localhost:8089/services/search/jobs/{sid}"

        while True:
            status = requests.get(status_check_url, params=parameters, auth=auth, verify=False, timeout=15)
            parsed_response = status.json()

            value = parsed_response.get("entry")
            value2 = value[0].get("content").get("isDone")

            if value2 == False:
                time.sleep(2)

            else:
                break

        results_url = f"https://localhost:8089/services/search/jobs/{sid}/results"
    
        results_response = requests.get(results_url, auth=auth, params=parameters, verify=False, timeout=15)

        
    except Exception as error:
        logging.error(f"Unexpected error occured: {error}. {response_splunk.json()}")

    else:
        return results_response.json()["results"]

def send_alert_to_hive(splunk_event_payload, thehive_url, api_key):
    
    try:
        headers = {
                "Authorization": f"Bearer {api_key}", 
                "Content-Type": "application/json"}
        
        for event in splunk_event_payload:
            attacker_ip = event.get('src_ip')
            targeted_ports = event.get('Target_Ports')
            requests_volume = event.get('Total_Volume_Hits')

            vt = virustotal_enrichment(attacker_ip,
                        virus_total_key = os.environ.get("vtkey"),
                        virus_total_url =  f"https://www.virustotal.com/api/v3/ip_addresses/{attacker_ip}"
                        )

            if vt == None:
                logging.error("VirusTotal is unavailable")

            else:
                payload = {"type": "splunk", 
                        "source": "Splunk - botsv1",
                        "sourceRef": f"{attacker_ip}-{time.time()}",
                        "title": "Suspicious recon and high volume requests on internal ports",
                        "description": f"The SPL query is structured to extracted values that can be used to identify and verify IOCs in this case its through the src_ip(attacker ip: {attacker_ip}), number of ports which where targeted for recon sweep scan ({targeted_ports}) and the total number of requests made ({requests_volume}). Through further investigation and intel gathering, VirusTotal has flagged this IP as malicious across {vt["malicious_count"]} engines, with an associated reputation score of {vt["reputation"]}.",
                        "severity": 1,
                        "tlp": 2}
        

                response = requests.post(thehive_url, headers=headers, json=payload, timeout=15)

               
                if response.status_code == 201:
                    logging.info("Successful Ingestion!")
                
                else:
                    logging.info(response.status_code)
                    print(response.text)
                

    except Exception as error:
        logging.error(f"Error occured: {error}")


if "__main__" == __name__:
    event_payload = fetch_splunk_alerts("https://localhost:8089/services/search/jobs",
            ("admin",os.environ.get("splunkpass") )
            ,{"search": 'search index=botsv1 sourcetype="stream:http" OR sourcetype="stream:tcp" | fields + src_ip, dest_port | stats count as "Total_Volume_Hits", dc(dest_port) as "Target_Ports" by src_ip | where Target_Ports > 50 | table src_ip, Target_Ports, Total_Volume_Hits | sort - Target_Ports',
                           "output_mode": "json"})

    send_alert_to_hive(event_payload, "http://192.168.100.158:9000/api/v1/alert", os.environ.get("thehivekey"))

    unique_set = {"T1595", "T1190", "T1059", "T1543.003"}
    attack_json_dictionary = build_mitre_layer(unique_set)
    export_attack_json(attack_json_dictionary)
