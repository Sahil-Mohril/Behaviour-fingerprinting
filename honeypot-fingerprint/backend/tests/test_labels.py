from app.labels import BEHAVIOURS, NO_DATA_SOURCE, UNKNOWN, behaviour_table, map_label


def test_dataset_labels_map_to_behaviours():
    assert map_label("BENIGN") == "benign"
    assert map_label("SSH-Patator") == "ssh_bruteforce"
    assert map_label("FTP-Patator") == "ftp_bruteforce"
    assert map_label("DoS Hulk") == "http_flood"
    assert map_label("DoS slowloris") == "slowloris"
    assert map_label("PortScan") == "port_scan_fast"
    assert map_label("Web Attack � Brute Force") == "web_bruteforce"
    assert map_label("Web Attack – XSS") == "web_vuln_probe"
    assert map_label("Syn") == "syn_flood"
    assert map_label("DrDoS_DNS") == "udp_flood"
    assert map_label("UDP-lag") == "udp_flood"
    assert map_label("PartOfAHorizontalPortScan") == "port_scan_fast"
    assert map_label("C&C-HeartBeat") == "botnet_c2"
    assert map_label("Benign") == "benign"
    assert map_label("") == "" and map_label("-") == ""
    assert map_label("something new") == UNKNOWN
    assert map_label("ssh_bruteforce") == "ssh_bruteforce"  # label overrides use behaviour keys


def test_no_data_source_behaviours_are_marked():
    table = {row["key"]: row for row in behaviour_table()}
    for key in ("crawler", "scraper", "icmp_flood"):
        assert table[key]["data_source"] == "no data source"
        assert table[key]["dataset_labels"] == []
    for key in NO_DATA_SOURCE:
        assert key in BEHAVIOURS
    assert table["ssh_bruteforce"]["data_source"] == "available"
