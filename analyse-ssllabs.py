# Tool for analysing SSL Labs JSON output
import json
import sys

# TODO: make configureable
ACCEPTED_GRADES = ['A', 'A+']
ACCEPTED_TLS_VERSION_IDS = [771, 772]
ACCEPTED_TLS_CIPHERSUITE_IDS = [
    0xC02F, 0xC02B, 0xC02C, 0xC030, 0xCCA8, 0xCCA9, 0x1301, 0x1302, 0x1303]
ACCEPTED_KEX_GROUP_IDS = [23, 24, 25, 29, 30]
MIN_EXPECTED_KEX_GROUP_IDS = [23] # TODO: add 29


def check_grades(obj):
    endpoints = obj['endpoints']
    grades = []
    for endpoint in endpoints:
        grades.append((endpoint["ipAddress"], endpoint["grade"]))

    # Parse the grades list
    accepted_hosts = []
    rejected_hosts = []
    for grade in grades:
        if grade[1] in ACCEPTED_GRADES:
            accepted_hosts.append(grade[0])
        else:
            rejected_hosts.append(grade[0])
    return accepted_hosts, rejected_hosts


def check_tls_config(obj):
    endpoints = obj['endpoints']
    for endpoint in endpoints:
        endpoint_details = endpoint["details"]
        protocols = endpoint_details["protocols"]
        protocol_ids = []
        for protocol in protocols:
            protocol_ids.append(protocol["id"])
        suites = endpoint_details["suites"]
        for protocol_id in protocol_ids:
            for suite_iter in suites:
                if suite_iter["protocol"] == protocol_id:
                    suite = suite_iter
                    break
            
            # Check cipher suites
            suite_list = suite["list"]
            for ciphersuite in suite_list:
                if ciphersuite["id"] not in ACCEPTED_TLS_CIPHERSUITE_IDS:
                    raise ValueError(f"Ciphersuite {ciphersuite['name']} is not acceptable for {obj['host']} ({endpoint['ipAddress']})!")
                else:
                    print(f"Got ciphersuite  {ciphersuite['name']} for {obj['host']} ({endpoint['ipAddress']})")
        
        # Check KEX groups
        kex_groups = endpoint_details["namedGroups"]["list"]
        expected_groups = MIN_EXPECTED_KEX_GROUP_IDS.copy()
        for kex_group in kex_groups:
            kex_id = kex_group["id"]
            if kex_id not in ACCEPTED_KEX_GROUP_IDS:
                raise ValueError(f"Named group {kex_group['name']} is not acceptable for {obj['host']} ({endpoint['ipAddress']})!")
            else:
                print(f"Got named group  {kex_group['name']} for {obj['host']} ({endpoint['ipAddress']})")
            if kex_id in expected_groups:
                expected_groups.remove(kex_id)
        if not len(expected_groups) == 0:
            raise ValueError(f"Named groups {expected_groups} are not supported for {obj['host']} ({endpoint['ipAddress']})!")



def main():
    if len(sys.argv) != 2:
        raise ValueError('Please provide the JSON file to read.')

    file_name = sys.argv[1]
    print(f'Reading {file_name}')

    with open(file_name, 'r') as json_file:
        data = json_file.read()
    json_obj = json.loads(data)

    # Only handle one element for now.
    assert(len(json_obj) == 1)
    json_obj = json_obj[0]

    accepted_hosts, rejected_hosts = check_grades(json_obj)
    if len(rejected_hosts) != 0:
        print(f"Not all hosts have acceptable grades: {rejected_hosts}")
    else:
        print(f"All hosts have acceptable grades ({accepted_hosts}).")
    
    check_tls_config(json_obj)


if __name__ == "__main__":
    main()
