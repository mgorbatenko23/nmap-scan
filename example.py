from nmap_scan import Nmap

if __name__ == '__main__':
    # ping scan
    nmap = Nmap()
    nmap.scan(['10.10.1.0/24'], '-v -sn -n')
    print(nmap.get_scan_result_as_dataclasses())

    # tcp/22 port scan
    nmap.scan(['10.10.1.0/24'], '-v -n -sS -p22')
    print(nmap.get_scan_result_as_json())

    # raw nmap output as dict
    print(nmap.get_raw_nmap_output_as_dict())
