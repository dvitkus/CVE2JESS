#Automatizuotas CVSS V2 įrašų konvertavimas į Jess ES faktus v2.0.1 2022.

import requests
import re
import zipfile
import json
from tqdm import tqdm
import pandas as pd
import numpy as np
from os import listdir, path, makedirs
from os.path import isfile, join

#CPE duomenu parsinimas
def extract_products(cpelist):
    if not cpelist:
        return('NONE')
    else:
        final=[]
        for entry in cpelist:
            f_ent='"'+np.array_str(np.apply_along_axis(' '.join, 0, np.char.capitalize(np.array(entry.split(':')[3:6])))).replace('\(', '').replace('\)', '').replace('\\', '')+'"'
            final.append(f_ent)
        return(' '.join(final))

#Tikrinama ar itrauktas i CISA kataloga ir atitinkamai pažymima 
def exploit_check(cve_id,exploited):
    rx = r'^' + cve_id + '$' 

    if exploited['cveID'].str.contains(rx).any():
        return " (known_exploited YES) (date_added_to_known_exploited "+exploited[exploited.cveID==cve_id].dateAdded.values[0]+")"
    else:
        return " (known_exploited NO) (date_added_to_known_exploited NO)"

#Uzkraunamas Meta failas jei egzistuoja
def load_cache_definitions():
    if not path.exists('nvd_cache.json'):
        c=open('nvd_cache.json', 'a')
        c.write("{}")
        c.close()
    c = open('nvd_cache.json')
    cache = json.load(c)
    c.close()
    return cache

#Issaugomi meta duomenys
def save_cache_definitions(cache):
    with open('nvd_cache.json', 'w') as c:
        json.dump(cache, c)

#Is NVD parsiunciami .zip archyvai
def download_json(meta):
    json_filename = meta.replace(".meta",".json.zip")
    r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + json_filename, stream=True)
    with open("nvd/" + json_filename, 'wb') as f:
        for chunk in r_file:
            f.write(chunk)

#Tikrinami meta duomenys
def nvd_definition_check():
    regex=re.compile('(?<=sha256:)([A-Z0-9]{64})')
    cache = load_cache_definitions()
    
    if not path.exists('nvd'):
        makedirs('nvd')

    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    all_meta = re.findall("nvdcve-1.1-[0-9a-z]*\.meta",r.text)
    
    for meta in tqdm(all_meta):
        r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.1/" + meta, stream=True)
        hash=regex.findall(r_file.text)[0]
        if meta in cache and path.exists('nvd_cache.json'):
            if cache[meta]!=hash:
                download_json(meta)
                cache[meta]=hash
            else:
                continue
        else:
            cache[meta]=hash
            download_json(meta)
    save_cache_definitions(cache)             

#Isarchyvuojami duomenys - json   
def unzip_cve():
    if not path.exists('data'):
        makedirs('data')
    files = [f for f in listdir('nvd/') if re.match(r'nvdcve-1.1-[0-9a-z]*\.json\.zip', f)]
    files.sort()
    print('\n',"Vykdomas duomenų išarchyvavimas:")
    for file in tqdm(files):
        archive = zipfile.ZipFile(join("nvd/", file), 'r')
        jsonfile = archive.open(archive.namelist()[0])
        cve_dict = json.loads(jsonfile.read())
        with open('data/'+file+'.json', 'w', encoding='utf-8') as f:
            json.dump(cve_dict, f, ensure_ascii=False, indent=4)
        jsonfile.close()

#CVE duomenu konvertavimas        
def read_json():
    files = [f for f in listdir('data/') if re.match(r'nvdcve-1.1-[0-9]*\.json', f)]
    files.sort()
    k=0
    processed=0
    accepted=0
    corrupted=0

    print('\n',"Vykdomas duomenų konvertavimas:")
    
    #Is CISA katalogo uzkraunami  CVE ID ir pridejimo data.
    exploited=pd.read_csv("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", usecols=[0,4])
    if not path.exists('jess'):
        makedirs('jess')
        
    open('jess/cve_jess_kb.dat', 'w').close()
    open('jess/jess_err.txt', 'w').close()
    
    output = open('jess/cve_jess_kb.dat', 'a')
    fail = open('jess/jess_err.txt', 'a')
    
    for file in tqdm(files):
        k+=1
        f = open (join("data/", file),encoding='utf-8')
        data = json.load(f)
        z=-1
        x=0    
                
        for i in data['CVE_Items']:
            z+=1
            skip=0 
            err_reason=''

            cve_id=i['cve']['CVE_data_meta']['ID']
            if len(i['cve']['description']['description_data'])!=1: 
                skip=0 
                err_reason+='---description_data not 1;'
            descr_data=i['cve']['description']['description_data'][0]['value']
            publishDate=i['publishedDate']
            lastModDate=i['lastModifiedDate']
            
            #Ar yra impact laukas - tikrinamas CVSS 2
            if "baseMetricV2" in i['impact']: 
                bMV2=i['impact']['baseMetricV2']
                cvssV2=bMV2['cvssV2']
                vecStr=cvssV2['vectorString']
                accStr=cvssV2['accessVector']
                accCmplx=cvssV2['accessComplexity']
                auth=cvssV2['authentication']
                confImp=cvssV2['confidentialityImpact']
                intImp=cvssV2['integrityImpact']
                avaImp=cvssV2['availabilityImpact']
                bScore=cvssV2['baseScore']
                severity=bMV2['severity']
                expScore=bMV2['exploitabilityScore']
                impScore=bMV2['impactScore']
                
            else:
                skip=1
                err_reason+='---no impact (baseMetricV2) data;'
            
            #Tikrinama cpe ar turi bent viena irasa
            nodes=i['configurations']['nodes']
            cpe_list=list()            
            if len(nodes)>0:
                for inod in nodes:                    
                    if len(inod['cpe_match'])>0:
                        for j in inod['cpe_match']:
                            if j['vulnerable']:
                                cpe_list.append(j['cpe23Uri'])

                    elif len(inod['children'])>0:
                        children=inod['children']
                        for child in children:
                            if len(child['cpe_match'])>0:
                                for nodd in child['cpe_match']:
                                    if nodd['vulnerable']:
                                        cpe_list.append(j['cpe23Uri'])
            else:
                skip=1
                err_reason+='---no nodes;'

            if skip==0:                
                str_1='(MAIN::vulnerability (id '+cve_id+') (publisheddate '+publishDate+') (lastmodifieddate '+lastModDate+') (description "'+descr_data.replace("\"", "'").replace('(', '').replace(')', '')
                str_2='") (cpe23uri '+' '.join(cpe_list)+') (vectorstring '
                str_3=vecStr+') (accessvector '+accStr+') (accesscomplexity '+accCmplx+') (authentication '+auth+') (confidentialityimpact '+confImp+') (integrityimpact '
                str_4=intImp+') (availabilityimpact '+avaImp+') (basescore '+str(bScore)+') (severity '+severity+') (exploitabilityscore '+str(expScore)+') (impactscore '+str(impScore)+')'
                str_5=exploit_check(cve_id,exploited)
                str_6=' (affected_products '+extract_products(cpe_list)+')'
                full_str=str_1+str_2+str_3+str_4+str_5+str_6+")"
                output.write(full_str)
                output.write('\n')
            else:
                e_out='item: '+str(z)+', reason(s): '+err_reason
                fail.write(e_out)
                fail.write('\n')
                x+=1
            
        processed=processed+(z+1)
        accepted=accepted+(z+1-x)
        corrupted=corrupted+(x) 
        
        print(file," - nuskaityta CVE įrašų:",z+1,", konvertuota CVSS V2 įrašų:",z+1-x,", netinkamų CVE įrašų:",x)
       
    print('\n',"CVE CVSS V2 įrašų konvertavimas į Jess ES faktus baigtas.")
    print('\n','Iš viso nuskaityta CVE įrašų:',processed,", konvertuota CVSS V2 įrašų į Jess ES faktus:",accepted,", atmesta CVE įrašų, kurie neturi CVSS V2 duomenų:",corrupted)

    output.close()
    fail.close()
    
#----------Main-------------
print("Automatizuotas CVE CVSS V2 įrašų konvertavimas į Jess ES faktus v2.0.1 2022")
print('\n\n',"Tikrinami CVE NVD duomenys, parsiunčiami nauji duomenys:")
nvd_definition_check()
unzip_cve()
read_json()
print(" ")
print("Konvertuotų faktų užkrovimui Jess ES galima naudoti paruoštą deftemplate šabloną, kuris apibrėžia laukus, kuriuos gali turėti įvedamas faktas:")
print('\n',"(deftemplate vulnerability (slot id (type string)) (slot publisheddate (type string)) (slot lastmodifieddate (type string)) (slot description (type string)) (multislot cpe23uri) (slot vectorstring (type string)) (slot accessvector (type string)) (slot accesscomplexity (type string)) (slot authentication (type string)) (slot confidentialityimpact (type string)) (slot integrityimpact (type string)) (slot availabilityimpact (type string)) (slot basescore (type float)) (slot severity (type string)) (slot exploitabilityscore (type float)) (slot impactscore (type float)) (slot known_exploited (type string)) (slot date_added_to_known_exploited (type string)) (multislot affected_products))")