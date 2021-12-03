import requests
import json
from getpass import getpass

def extract_values(obj, key):
    """Pull all values of specified key from JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results

def obtenir_switch_ports_politiques(ip_fgt,vdom,user_FGT,password_FGT):

    if (password_FGT == "ASK"):
       presenta = "Credencials de l'usuari "+user_FGT+" per al vdom "+vdom+" al FGT "+ip_fgt+":"
       password = getpass(prompt=presenta)
    else:
       password = password_FGT

    
    url_login = "https://"+str(ip_fgt)+"/logincheck"
    client = requests.session()
    payload = "username="+user_FGT+"&secretkey="+password
    r = client.post(url_login, data=payload, verify=False)
    apscookie=r.cookies
    #print (client.cookies)
    if not client.cookies:
       exit("Contrasenya/usuari incorrecte")
    for cookie in client.cookies:
        if cookie.name == 'ccsrftoken':
            csrftoken = cookie.value[1:-1] # token stored as a list
            client.headers.update({'X-CSRFTOKEN': csrftoken})

    # obtenim el llistat de ports del vdom. ho passem a json i cerquem port-name,descr i switchid
    
    url_cmdb="https://"+ip_fgt+"/api/v2/cmdb/switch-controller/managed-switch/?vdom="+vdom+"&format=ports"
    r = client.get(url_cmdb, cookies=apscookie, verify=False)
    y = json.loads(r.text)
    llistat_ports = extract_values(r.json(), 'port-name')
    alias_ports = extract_values(r.json(), 'description')
    switch = extract_values(r.json(), 'switch-id')

    # cerquem quins ports tenen alias que comenca per PUR_ , politica us raonable, o S_PUR_ politica us
    # raonable de Servidors

    i = 0
    switch_f = []
    alias_ports_f = []
    llistat_ports_f = []
    for value in llistat_ports:
        if alias_ports[i].startswith("PUR_") or alias_ports[i].startswith("S_PUR_"):
           #print ("al switch " + switch[i]+" el "+ llistat_ports[i]+" li correspon la politica: "+ alias_ports[i])
           # ara creem les variables finals, amb nomes els ports amb alias de politica us raonable 
           switch_f.append(switch[i])
           llistat_ports_f.append(llistat_ports[i])
           if (alias_ports[i].startswith("PUR_")):
              alias_ports_f.append("PUR")
           if (alias_ports[i].startswith("S_PUR_")):
              alias_ports_f.append("S_PUR")
        i = i + 1
    # crearem un diccionari indexat per noms (switch_f)  amb la IP de cada switch
    url_cmdb="https://"+ip_fgt+"/api/v2/monitor/switch-controller/managed-switch/select/?vdom="+vdom
    r = client.get(url_cmdb, cookies=apscookie, verify=False)
    y = json.loads(r.text)
    name_o = extract_values(r.json(), 'serial')
    name = name_o[0]
    #print(name)
    ip = extract_values(r.json(), 'connecting_from')
    ip_f = ip[0]
    #print(ip_f)
    j = 0
    commutadors_totals = {}
    for variable in ip:
        commutadors_totals[name_o[j]] = ip[j] 
        j = j + 1
 
    # crearem un diccionari nomes dels switchos que tinguin al menys un port a configurar
    commutadors = {}
    for variable1 in switch_f:
        commutadors[variable1] = commutadors_totals[variable1]

    return switch_f,llistat_ports_f,alias_ports_f,commutadors


def aplicar_politica(ports_switch,politica_switch,commutadors,switch_f,user_FSW,password_FSW):

    if (password_FSW == "ASK"):
       presenta = "Credencials de l'usuari admin (dels commutadors):"
       password = getpass(prompt=presenta)
    else:
       password = password_FSW
 
    for sn_switch in commutadors:
        print ("Connexio  a: "+sn_switch+" IP: "+commutadors[sn_switch])
        url_login="https://"+commutadors[sn_switch]+"/logincheck"
        client = requests.session()
        payload = "username="+user_FSW+"&secretkey="+password
        r = client.post(url_login, data=payload, verify=False)
        apscookie=r.cookies
        if not client.cookies:
           exit("Contrasenya/usuari incorrecte")
        for cookie in client.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1] # token stored as a list
                client.headers.update({'X-CSRFTOKEN': csrftoken})

        # Primer comprovem si estan creats els SERVICE CUSTOM que es necesiten a les
        # politiques, pe TCP source 25 -> SERVIDOR_SMTP
        
        url_acl_get="https://"+commutadors[sn_switch]+"/api/v2/cmdb/switch.acl.service/custom"
        r = client.get(url_acl_get, cookies=apscookie, verify=False)
        services = extract_values(r.json(), 'name')
        #print (services)  # Services son els custom services configurats al switch
     
        # obro fitxer custom_services que son els custom services que volem crear
        # comprovo si existeixin al switch. Si no existeixen els afegeixo, si ja 
        # existeixen no cal fer res
        
        with open ('custom_services', 'r') as outfile:
             for line in outfile:
                 if not line.startswith("#"):
                    line1 = json.loads(line)
                    serveis = extract_values(line1, 'name')
                    for val in serveis:
                        if val not in services:
                           #print ("NOU:"+ str(val))
                           r = client.post(url_acl_get, data=json.dumps(line1), cookies=apscookie, verify=False)
                           print (r.json)
                        #else:
                           #print (val + " Ja existeix")
        
        # Segon mirem quines politiques hi ha instalades, les esborrarem per aplicar les noves
        
        url_acl_post="https://"+commutadors[sn_switch]+"/api/v2/cmdb/switch.acl/policy"
        r = client.get(url_acl_post, cookies=apscookie, verify=False)
        id= extract_values(r.json(), 'id')
        print (id)

       # print ("Esborro politiques")

        for vari in id:
            #print (vari,id)
            url_acl_post="https://"+commutadors[sn_switch]+"/api/v2/cmdb/switch.acl/policy/"+str(vari)
            r = client.delete(url_acl_post, cookies=apscookie, verify=False)
            print (r.json)

        url_acl_post="https://"+commutadors[sn_switch]+"/api/v2/cmdb/switch.acl/policy/"
        
        llistat_ports_pur = "" 
        llistat_ports_s_pur = ""
        i=0
        for valor in politica_switch[sn_switch]:
            if (valor == "PUR"):
               print ("el "+ports_switch[sn_switch][i]+" afegit a "+valor)
               cadena = "{\"member-name\":\""+ports_switch[sn_switch][i]+"\"},"
               llistat_ports_pur+=cadena
            elif (valor == "S_PUR"):
               print ("el "+ports_switch[sn_switch][i]+" afegit a "+valor)
               cadena = "{\"member-name\":\""+ports_switch[sn_switch][i]+"\"},"
               llistat_ports_s_pur+=cadena
            i = i + 1
        #print (ports_switch[sn_switch])
        #print (politica_switch[sn_switch])
        llistat_ports_s_pur=llistat_ports_s_pur.rstrip(",")
        llistat_ports_pur=llistat_ports_pur.rstrip(",")
        #print (llistat_ports_s_pur)
        #print (llistat_ports_pur)

        with open ('politica_us_raonable_general', 'r') as outfile:
             for line in outfile:
                 if not line.startswith("#"):
                    # primer inserim llistat de ports
                    index = line.find("%")
                    output_line = line[:index] + llistat_ports_pur + line[index:].lstrip("%")
                    line1 = json.loads(output_line)
                    #print (line1)
                    r = client.post(url_acl_post, data=json.dumps(line1), cookies=apscookie, verify=False)
                    print (r.json)

        with open ('politica_us_raonable_servidors', 'r') as outfile:
             for line in outfile:
                 if not line.startswith("#"):
                    # primer inserim llistat de ports
                    index = line.find("%")
                    output_line = line[:index] + llistat_ports_s_pur + line[index:].lstrip("%")
                    line1 = json.loads(output_line)
                    r = client.post(url_acl_post, data=json.dumps(line1), cookies=apscookie, verify=False)
                    print (r.json)


#################################################################################################################
###############################################################################################################
# Programa per aplicar politica d'us raonable a tots els commutadors Fortinet
# 
# El requisit es asignar alias als ports dels commutadors amb el prefixe : PUR_ o S_PUR_
# Permet dues politiques PUR_: politica general i S_PUR_: politica adrecada a Servidors
#
# S'ha d'indicar Fortigate i vdom  (que gestiona els switchos) i l'usuari. 
# Es demana passwd per no guardar-ho a l'script
# Es pot generar un fitxer de conf amb aquesta informacio
# Tambe cal el usuari/passwd dels switchos. S'enten que es el mateix per tots

with open ('politica_us_raonable.conf', 'r') as outfile:
     for line in outfile:
         if not line.startswith("#"):
            line1 = json.loads(line)
            line2 = extract_values(line1, 'IP_FGT')
            line3 = extract_values(line1, 'user_FGT')
            line4 = extract_values(line1, 'password_FGT')
            line5 = extract_values(line1, 'vdom')
            line6 = extract_values(line1, 'user_FSW')
            line7 = extract_values(line1, 'password_FSW')
            IP_FGT = line2[0]
            user_FGT = line3[0]
            password_FGT = line4[0]
            vdom = line5[0]
            user_FSW = line6[0]
            password_FSW = line7[0]

#print (IP_FGT , user_FGT , password_FGT , vdom , user_FSW , password_FSW)

if not (IP_FGT or user_FGT or password_FGT or vdom or user_FSW or password_FSW):
   exit("Fitxer de configuracio incorrecte, falta parametre")



# primer ens connectem al Fortigate per veure quins switchos tenim i el llistat de ports amb politica configurada
# (alias de port ha de comencar amb PUR_ o S_PUR_

switch_f,llistat_ports_f,alias_ports_f,commutadors = obtenir_switch_ports_politiques(IP_FGT,vdom,user_FGT,password_FGT)

# creo dos diccionaris, els dos indexats pel nom del switch.un de ports i un altre de politiques. Estan ordenats.
# el item 1 d'un diccionari correspon al item 1 de l'altre. de forma que aixi sabem quina politica aplicar
# a cada port

ports_switch = dict()
politica_switch = dict()
i = 0
for value in switch_f:
    if value in ports_switch:
       ports_switch[value].append(llistat_ports_f[i])
    else:
       ports_switch[value] = [llistat_ports_f[i]] # el 
    if value in politica_switch:
       politica_switch[value].append(alias_ports_f[i])
    else:
       politica_switch[value] = [alias_ports_f[i]]

    print ("al switch " + switch_f[i]+" el "+ llistat_ports_f[i]+" li correspon la politica: "+ alias_ports_f[i])
    print ("la IP del swith es:"+commutadors[switch_f[i]])
    i = i + 1

#print (ports_switch[switch_f[0]])
#print (politica_switch[switch_f[0]])
aplicar_politica(ports_switch,politica_switch,commutadors,switch_f,user_FSW,password_FSW)

