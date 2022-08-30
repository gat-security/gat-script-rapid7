import csv
from datetime import datetime
import json
import time
import defusedxml.ElementTree as Et
import re
import os
import requests as requests

maior = 0
quando = ""
directory = 'src/xmls'

config_file = open("./src/config.json")
config = json.load(config_file)
config_file.close()

hora_log = str(datetime.now()).replace(":", "-").replace(" ", "T")
log_file = open("./src/logs/log_{}.txt".format(hora_log), "a", newline='')

url = config['url']
bearer = config['bearer']
resource = '/app/vulnerability/upload/api/Rapid7/'
resources = [config['templates']['InsightVM']]

# Files
for input in os.listdir(directory):
    f = os.path.join(directory, input)

    input_split = input.split('.')
    if input_split[1] != 'xml':
        continue

    output_name = input_split[0] + '.csv'
    file_and_path = './src/csvs/' + output_name

    log_file.write("[+] {} [+]\n".format(file_and_path))

    tree = Et.parse('./src/xmls/' + input)
    root = tree.getroot()

    output_file = open(file_and_path, "a", newline='', encoding="utf-8")
    writer = csv.writer(output_file, delimiter=';', quoting=csv.QUOTE_ALL)

    changed = 0

    # Escolha do Report
    if root.tag == "NexposeReport":  # SCAP/ASSET_REPORT
        print("Iniciando NexposeReport...")

        version = root.attrib['version']
        ref_header_titulo = ['ref_titulo_1', 'ref_titulo_2', 'ref_titulo_3', 'ref_titulo_4', 'ref_titulo_5',
                             'ref_titulo_6', 'ref_titulo_7', 'ref_titulo_8', 'ref_titulo_9', 'ref_titulo_10',
                             'ref_titulo_11', 'ref_titulo_12', 'ref_titulo_13', 'ref_titulo_14', 'ref_titulo_15',
                             'ref_titulo_16']

        ref_header_url = ['ref_url_1', 'ref_url_2', 'ref_url_3', 'ref_url_4', 'ref_url_5',
                          'ref_url_6', 'ref_url_7', 'ref_url_8', 'ref_url_9', 'ref_url_10',
                          'ref_url_11', 'ref_url_12', 'ref_url_13', 'ref_url_14', 'ref_url_15',
                          'ref_url_16']

        j = 0
        i = 0
        vulnerability = 0
        issue = 0
        issue_fail = 0
        nodes = 0
        ipv6_list = []
        ipv6_issue = 0

        while root[j].tag != 'VulnerabilityDefinitions':
            if root[j].tag == "nodes":
                nodes = j
            j += 1

        for i in root[j]:

            references = ""
            reference_title = []
            reference_url = []
            tags = ""
            tag_list = []
            exploits = ""
            exploit_id = ""
            exploit_title = ""
            solution = ""
            paragraph = 0
            description = ""
            malware_name = ""
            published_date = ""
            modified_date = ""
            added_date = ""
            sev = [1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5]
            exploit_attribs = ['id', 'title', 'type', 'link', 'skillLevel']
            x = 0

            # Vulnerabilidades
            for k in root[j][vulnerability]:

                published_date = root[j][vulnerability].attrib['published'].split('T')[0]
                published_date = published_date[:4] + "-" + published_date[4:6] + "-" + published_date[6:]

                added_date = root[j][vulnerability].attrib['added'].split('T')[0]
                added_date = added_date[:4] + "-" + added_date[4:6] + "-" + added_date[6:]

                modified_date = root[j][vulnerability].attrib['modified'].split('T')[0]
                modified_date = modified_date[:4] + "-" + modified_date[4:6] + "-" + modified_date[6:]

                if root[j][vulnerability][x].tag == 'description':
                    d = 0
                    for g in root[j][vulnerability][x][0]:
                        paragraph = 1
                        d += 1
                    if paragraph == 1:
                        description = root[j][vulnerability][x][0][0].text
                    else:
                        description = root[j][vulnerability][x][0].text
                description = description.replace("\n", "")
                description = description.replace("  ", " ")

                if root[j][vulnerability][x].tag == 'malware':
                    d = 0
                    for g in root[j][vulnerability][x]:
                        malware_name = root[j][vulnerability][x][0].text

                if root[j][vulnerability][x].tag == 'exploits':
                    d = 0
                    exploit = ""
                    for g in root[j][vulnerability][x]:
                        for attrib in exploit_attribs:
                            if attrib == "id":
                                exploit_id += root[j][vulnerability][x][d].attrib[attrib] + ", "
                            if attrib == "title":
                                exploit_title += root[j][vulnerability][x][d].attrib[attrib] + ", "
                            exploit += attrib + ": " + root[j][vulnerability][x][d].attrib[attrib] + ", "
                        exploits = exploit + '| '
                        d += 1
                exploits = exploits[:-2]
                exploit_id = exploit_id[:-2]
                exploit_title = exploit_title[:-2]

                if root[j][vulnerability][x].tag == 'tags':
                    d = 0
                    for g in root[j][vulnerability][x]:
                        tags = root[j][vulnerability][x][d].text + ', '
                        d += 1
                    tags = tags[:-2]

                if root[j][vulnerability][x].tag == 'references':
                    d = 0
                    for g in root[j][vulnerability][x]:
                        if root[j][vulnerability][x][d].attrib['source'] == "URL":
                            reference_url.append(root[j][vulnerability][x][d].text)
                            if root[j][vulnerability][x][d].text.split("/")[-1] == "":
                                reference_title.append(root[j][vulnerability][x][d].text.split("/")[-2])
                            else:
                                reference_title.append(root[j][vulnerability][x][d].text.split("/")[-1])

                        d += 1

                if root[j][vulnerability][x].tag == 'solution':
                    solution = Et.tostring(
                        root[j][vulnerability][x][0], encoding='utf-8', method='text').decode("utf-8")
                    solution = solution.replace("	", "")
                    solution = solution.replace("  ", "")
                    solution = solution.replace("\n", "")
                    if solution == "":
                        solution = "Sem solução cadastrada"

                x += 1

            k = 0
            vuln_ativo = 1
            # Ativos
            for node in root[nodes]:
                test_salvos = []
                end_test_salvos = []
                operating_system = ""
                operating_system_list = []
                certainty_list = []
                certainty = ""

                address = root[nodes][k].attrib['address']

                # ----------------------------------------------------------------------------------------------------
                for fingerprint in root[nodes][k].findall("./fingerprints/os"):
                    try:
                        operating_system_list.append(fingerprint.attrib['product'])
                        certainty_list.append(fingerprint.attrib['certainty'])
                    except:
                        certainty = 0
                        operating_system = "Não Cadastrado"

                try:

                    if version == "2.0":
                        operating_system = operating_system_list[0]
                        certainty = certainty_list[0]
                except:
                    certainty = 0
                    operating_system = "Não Cadastrado"

                for endpoint in root[nodes][k].findall("./endpoints/endpoint"):
                    protocol = endpoint.attrib['protocol']
                    port = endpoint.attrib['port']
                    test_status = ""
                    for test in endpoint.findall('./services/service/tests/test'):
                        if root[j][vulnerability].attrib['id'] == test.attrib['id'] \
                                and test.attrib['status'] != "not-vulnerable" \
                                and not test.attrib['id'] in end_test_salvos:
                            vuln_ativo = 1
                            test_status = test.attrib['status']
                            end_test_salvos.append(test.attrib['id'])

                            # Write row
                            if version == "2.0":
                                header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                          'title', 'severity',
                                          'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                          'modified', 'riskScore', 'description',
                                          'tags', 'solution']

                                for ref in range(len(ref_header_url)):
                                    header.append(ref_header_titulo[ref])
                                    header.append(ref_header_url[ref])

                                data = [address, port, protocol, operating_system,
                                        certainty, test_status, root[j][vulnerability].attrib['id'],
                                        root[j][vulnerability].attrib['title'],
                                        sev[int(root[j][vulnerability].attrib['severity'])],
                                        root[j][vulnerability].attrib['cvssScore'],
                                        malware_name, exploit_id, exploit_title, published_date,
                                        added_date,
                                        modified_date,
                                        root[j][vulnerability].attrib['riskScore'], description, tags,
                                        solution]

                                for ref in range(len(reference_url)):
                                    data.append(reference_title[ref])
                                    data.append(reference_url[ref])

                                if ":" not in address:
                                    if os.path.getsize(file_and_path) == 0 and changed == 0:
                                        changed = 1
                                        writer.writerow(header)
                                    writer.writerow(data)
                                    issue += 1
                                else:
                                    log_file.write("\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}'"
                                                   "-> IPv6\n".format(address, port, root[j][vulnerability].attrib['id']
                                                                      , sev[int(
                                                                        root[j][vulnerability].attrib['severity'])]))
                                    issue_fail += 1

                            elif version == "1.0":

                                header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                          'title', 'severity',
                                          'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                          'modified', 'riskScore', 'description',
                                          'tags', 'solution']

                                for ref in range(len(ref_header_url)):
                                    header.append(ref_header_titulo[ref])
                                    header.append(ref_header_url[ref])

                                data = [address, port, protocol, "Sistema Operacional não cadastrado",
                                        "", test_status, root[j][vulnerability].attrib['id'],
                                        root[j][vulnerability].attrib['title'],
                                        sev[int(root[j][vulnerability].attrib['severity'])],
                                        root[j][vulnerability].attrib['cvssScore'], '', '',
                                        '',
                                        published_date,
                                        added_date,
                                        modified_date, "", description, tags,
                                        solution]

                                for ref in range(len(reference_url)):
                                    data.append(reference_title[ref])
                                    data.append(reference_url[ref])

                                if ":" not in address:
                                    if os.path.getsize(file_and_path) == 0 and changed == 0:
                                        changed = 1
                                        writer.writerow(header)
                                    writer.writerow(data)
                                    issue += 1
                                else:
                                    log_file.write("\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}'"
                                                   "-> IPv6\n".format(address, port, root[j][vulnerability].attrib['id']
                                                                      , sev[int(
                                                                        root[j][vulnerability].attrib['severity'])]))
                                    issue_fail += 1

                for test in root[nodes][k].findall("./tests/test"):
                    port = "0"
                    protocol = ""
                    test_status = ""

                    if root[j][vulnerability].attrib['id'] == test.attrib['id'] \
                            and test.attrib['status'] != "not-vulnerable" \
                            and not test.attrib['id'] in test_salvos:

                        vuln_ativo = 1
                        test_status = test.attrib['status']
                        test_salvos.append(test.attrib['id'])

                        # Write row
                        if version == "2.0":
                            header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                      'title', 'severity',
                                      'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                      'modified', 'riskScore', 'description',
                                      'tags', 'solution']

                            for ref in range(len(ref_header_url)):
                                header.append(ref_header_titulo[ref])
                                header.append(ref_header_url[ref])

                            data = [address, port, protocol, operating_system,
                                    certainty, test_status, root[j][vulnerability].attrib['id'],
                                    root[j][vulnerability].attrib['title'],
                                    sev[int(root[j][vulnerability].attrib['severity'])],
                                    root[j][vulnerability].attrib['cvssScore'],
                                    malware_name, exploit_id, exploit_title, published_date,
                                    added_date,
                                    modified_date,
                                    root[j][vulnerability].attrib['riskScore'], description, tags,
                                    solution]

                            for ref in range(len(reference_url)):
                                data.append(reference_title[ref])
                                data.append(reference_url[ref])

                            if ":" not in address:
                                if os.path.getsize(file_and_path) == 0 and changed == 0:
                                    changed = 1
                                    writer.writerow(header)
                                writer.writerow(data)
                                issue += 1
                            else:
                                log_file.write("\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}'"
                                               "-> IPv6\n".format(address, port, root[j][vulnerability].attrib['id']
                                                                  , sev[int(
                                                                    root[j][vulnerability].attrib['severity'])]))
                                issue_fail += 1

                        elif version == "1.0":
                            header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                                      'title', 'severity',
                                      'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                                      'modified', 'riskScore', 'description',
                                      'tags', 'solution']

                            for ref in range(len(ref_header_url)):
                                header.append(ref_header_titulo[ref])
                                header.append(ref_header_url[ref])

                            data = [address, port, protocol, "Sistema Operacional não cadastrado", "",
                                    test_status, root[j][vulnerability].attrib['id'],
                                    root[j][vulnerability].attrib['title'],
                                    sev[int(root[j][vulnerability].attrib['severity'])],
                                    root[j][vulnerability].attrib['cvssScore'], '', '', '',
                                    published_date,
                                    added_date,
                                    modified_date, "", description, tags,
                                    solution]

                            for ref in range(len(reference_url)):
                                data.append(reference_title[ref])
                                data.append(reference_url[ref])

                            if ":" not in address:
                                if os.path.getsize(file_and_path) == 0 and changed == 0:
                                    changed = 1
                                    writer.writerow(header)
                                writer.writerow(data)
                                issue += 1
                            else:
                                log_file.write("\tApontamento não cadastrado '{} porta:{} - {} | Severidade: {}'"
                                               "-> IPv6\n".format(address, port, root[j][vulnerability].attrib['id']
                                                                  , sev[int(
                                                                    root[j][vulnerability].attrib['severity'])]))
                                issue_fail += 1
                k += 1

            vulnerability += 1
        if version == "2.0":
            resource = '/app/vulnerability/upload/api/{}/'.format(resources[0])
        else:
            resource = '/app/vulnerability/upload/api/{}/'.format(resources[0])
        print("Total NexposeReport (" + input + "):", issue)
        log_file.write("\n\tApontamentos convertidos: {}".format(issue))
        if issue_fail > 0:
            log_file.write("\n\tApontamentos não convertidos: {}\n\n".format(issue_fail))

    elif root.tag == "SCAN":  # QUALYS
        ref_header_titulo = ['ref_titulo_1', 'ref_titulo_2', 'ref_titulo_3', 'ref_titulo_4', 'ref_titulo_5',
                             'ref_titulo_6', 'ref_titulo_7', 'ref_titulo_8', 'ref_titulo_9', 'ref_titulo_10',
                             'ref_titulo_11', 'ref_titulo_12', 'ref_titulo_13', 'ref_titulo_14', 'ref_titulo_15',
                             'ref_titulo_16']

        ref_header_url = ['ref_url_1', 'ref_url_2', 'ref_url_3', 'ref_url_4', 'ref_url_5',
                          'ref_url_6', 'ref_url_7', 'ref_url_8', 'ref_url_9', 'ref_url_10',
                          'ref_url_11', 'ref_url_12', 'ref_url_13', 'ref_url_14', 'ref_url_15',
                          'ref_url_16']

        print("Iniciando QualysGuard...")
        vulnerability = 0

        for ativo in root.findall('./IP'):
            address = ativo.attrib['value']
            for cat in ativo.findall('./VULNS/CAT'):
                try:
                    port = cat.attrib['port']
                    protocol = cat.attrib['protocol']
                except:
                    port = 0
                    protocol = ""

                for vuln in cat.findall('./VULN'):

                    id_vuln = vuln.attrib['number']
                    severity = vuln.attrib['severity']
                    try:
                        cveid = vuln.attrib['cveid']
                    except:
                        cveid = ''

                    title = vuln.find('./TITLE').text

                    ref_title = []
                    ref_url = []

                    for reference in vuln.findall('./CVE_ID_LIST/CVE_ID'):
                        ref_title.append(reference.find('./ID').text)
                        ref_url.append(reference.find('./URL').text)

                    remove_tag = re.compile('<.*?>')
                    solution = re.sub(remove_tag, "", Et.tostring(
                        vuln.find('./SOLUTION'), encoding='utf-8', method='text').decode("utf-8"))
                    diagnosis = re.sub(remove_tag, "", Et.tostring(
                        vuln.find('./DIAGNOSIS'), encoding='utf-8', method='text').decode("utf-8"))
                    result = re.sub(remove_tag, "", Et.tostring(
                        vuln.find('./RESULT'), encoding='utf-8', method='text').decode("utf-8"))

                    solution = solution.replace("	", "")
                    solution = solution.replace("  ", "")
                    solution = solution.replace("\n", "")

                    result = result.replace("	", "")
                    result = result.replace("  ", "")
                    result = result.replace("\n", "")

                    # Write row

                    header = ['address', 'port', 'protocol', 'os', 'certainty', 'test_status', 'id',
                              'title', 'severity',
                              'cvssScore', 'malware', 'exploit_id', 'exploit_title', 'published', 'added',
                              'modified', 'riskScore', 'description',
                              'tags', 'solution']

                    for ref in range(len(ref_header_url)):
                        header.append(ref_header_titulo[ref])
                        header.append(ref_header_url[ref])

                    data = [address, port, protocol, "Sistema Operacional não Cadastrado", "", "",
                            id_vuln, title, severity, "", "", "", "", '', '', '',
                            '', diagnosis + " " + result, cveid, solution]

                    for ref in range(len(ref_url)):
                        data.append(ref_title[ref])
                        data.append(ref_url[ref])

                    if os.path.getsize(file_and_path) == 0 and changed == 0:
                        changed = 1
                        writer.writerow(header)
                    writer.writerow(data)

                    vulnerability += 1

        resource = '/app/vulnerability/upload/api/{}/'.format(resources[0])
        print("Total QualysGuard (" + input + "):", vulnerability)
        log_file.write("\n\tApontamentos convertidos: {}\n".format(vulnerability))

    output_file.close()

    # Divide se necessario
    to_export = []
    file_size = os.path.getsize(file_and_path)
    max_size = 80 * 1024 * 1024
    div = 0

    if file_size > max_size:

        if div == 1:
            file_number = 1
            filename = './src/csvs/{}_{}.csv'.format(input_split[0], file_number)
            csvfile = open(file_and_path, 'r', encoding="utf-8").readlines()

            size = 0
            file = open(filename, 'a', encoding="utf-8")
            for i in range(len(csvfile)):
                file.write(csvfile[i])
                size = size + len(csvfile[i].encode('utf-8'))
                if size >= max_size:
                    file.close()
                    size = 0
                    to_export.append(filename)
                    file_number += 1
                    filename = './src/csvs/{}_{}.csv'.format(input_split[0], file_number)
                    file = open(filename, 'a', encoding="utf-8")
                    file.write(csvfile[0])
                    size = size + len(csvfile[i].encode('utf-8'))

            file.close()
            to_export.append(filename)
            os.remove(file_and_path)
            print("Divisão terminada. Foram criados {} arquivos".format(file_number))

        log_file.write("\t[!] Não foi possível fazer o upload do arquivo. Tamanho máximo suportado: 80Mb\n")
    else:
        to_export.append(file_and_path)

    # Export Custom Parser
    protocol = "https"
    gatPoint = "{}://{}{}".format(protocol, url, resource)

    for file_to_export in to_export:
        if file_to_export.split('.')[2] != 'csv':
            continue
        try:
            print("\nIniciando exportação do arquivo '{}'".format(file_to_export))
            with open(file_to_export, "rb") as export_file:
                name_csv = os.path.basename(file_to_export)
                file_dict = {'file': (name_csv, export_file, "text/csv", {'Expires': "0"})}
                with requests.Session() as s:
                    s.headers = {
                        'Authorization': 'Bearer %s' % bearer,
                        'cache-control': "no-cache"
                    }
                    r = s.request('POST', gatPoint, files=file_dict)
                    response = json.loads(r.text)
                    print("{} - {}".format(datetime.now().strftime(
                        "%Y-%m-%d-%I:%M:%S"
                    ), response))
                    log_file.write("\t\t{} - {}\n".format(datetime.now().strftime(
                        "%Y-%m-%d-%I:%M:%S"
                    ), response))

                    if response['processing_status'][0]['step'] == 1 and not response['processing_status'][0][
                        'completed']:
                        while not response['processing_status'][0]['completed']:
                            scanResou = "/api/v1/scans/{}".format(response['scan_id'])
                            scanPoint = "{}://{}{}".format(protocol, url, scanResou)

                            r = s.request('GET', scanPoint, {})
                            response = json.loads(r.text)
                            print(
                                "{} - response Upload GAT: {}".format(datetime.now().strftime(
                                    "%Y-%m-%d-%I:%M:%S"
                                ), response)
                            )
                            log_file.write("\t\t{} - response Upload GAT: {}\n".format(datetime.now().strftime(
                                "%Y-%m-%d-%I:%M:%S"
                            ), response))
                            time.sleep(10)

        except Exception as e:
            print("{} - Upload Error: {}".format(datetime.now().strftime(
                "%Y-%m-%d-%I:%M:%S"
            ), e))
            log_file.write("\t\t{} - Upload Error: {}\n".format(datetime.now().strftime(
                "%Y-%m-%d-%I:%M:%S"
            ), e))
    print("\n")
    log_file.write("\n[-] {} [-]\n\n\n".format(file_and_path))

log_file.close()
