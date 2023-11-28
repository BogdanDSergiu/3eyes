import re
import argparse
import yaml
import sys
import time
import platform
import os
from urllib.parse import urlparse
from colorama import just_fix_windows_console
import asyncio
import httpx
    


banner = """
\x1b[38;5;69m      _______                         
     |   _   |.-----.--.--.-----.-----.
     |___|   ||  -__|  |  |  -__|__ --|
      _(__   || ____|___  |_____|_____|
     |:  |   |      |_____|           
     |::.. . |               {ver}        
     `-------'               
\x1b[39m
"""

get_text = {
    'arg': {
        'description': "Tool's command line arguments.",
        'module': "Path to the YAML module used for fingerprinting.",
        'input': "File path containing a list of target URLs.",
        'target': "URL intended for fingerprinting.",
        'check_versionsList': "Versions list for comparison.",
        'set_outputString': "String format defining output presentation.",
        'set_moduleversions': "Specified versions for target checking.",
        'set_timeOut': "Timeout specification for requests.",
        'verbose_mode': "Outputs valid URL(s) with extra details.",
        'silent_mode': "Outputs only valid URL(s)."
    },
    'yaml_check' : {
        'metadata_missing': "\x1b[31m[!] Module Error\x1b[39m: The meta tag structure is incomplete or the version is missing",
        'metadata_version_missing': "\n\x1b[31m[!] Module Error\x1b[39m: The 'version' in meta tag is missing",
        'request_config_format': "\x1b[31m[!] Module Error\x1b[39m: The 'request' tag configuration is not in the correct format",
        'unsupported_method': "\x1b[31m[!] Module Error\x1b[39m: The request method '{method}' in the request configuration is not supported",
        'post_data_missing': "\x1b[31m[!] Module Error\x1b[39m: Post data is mandatory if the request method is POST",
        'url_path_incorrect' : "\x1b[31m[!] Module Error\x1b[39m: The 'url' in the request tag must start with a forward slash ('/')",
        'detect_missing': "\x1b[31m[!] Module Error\x1b[39m: The detect section is missing or improperly structured", # for future versions
        'versions_missing': "\x1b[31m[!] Module Error\x1b[39m: The version information is missing or improperly structured",
        'version_structure_incomplete': "\x1b[31m[!] Module Error\x1b[39m: The version structure is incomplete or missing essential elements",
        'missing_name': "\x1b[31m[!] Module Error\x1b[39m: The 'name' dose not exists within the version tag",
        'missing_match_rules': "\x1b[31m[!] Module Error\x1b[39m: Neither the 'match_string' nor the 'match_regex' rule exists in the '{version_name}' tag",
    },
    'error': {
        'fileNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: File '{value}' not found.\n",
        'yamlNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: Module name not found.\n",
        'moduleNotSet':'\x1b[31m[!] Input Error\x1b[39m: No module file provided',
        'moduleFileNotFound' : "\n\n\x1b[31m[!] Input Error\x1b[39m: The module '{value}.yaml' was not found in the 'modules' folder.",
        'moduleVersionNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: Module '{version_name}' not found in configuration.",
        'invalidTimeOutFormat': "\n\n\x1b[31m[!] Input Error\x1b[39m: Invalid timeout value '{value}'",
        'invalidOutputFormat': "\n\n\x1b[31m[!] Input Error\x1b[39m: Invalid key(s) in output format '{value}'",
        'noTarget': '\x1b[31m[!] Input Error\x1b[39m: Please provide -t or -i to specify the input source.'
    },
    'info': {
        'targetFound': '\x1b[32m[-] Found\x1b[39m: {url}',
        'targetNotFound': '\x1b[31m[-] {msg}\x1b[39m: {url}',
        'noVerMatch': '\x1b[31m[-] NoVerMatch\x1b[39m: {url}',
        'noMatch': 'NoMatch',
        'timeOut': 'TimeOut',
        'statusCode': 'StatusCode',
        'networkError': 'NetworkError',
        'protocol': 'Protocol',
        'default_outputFormat': "\x1b[32m[-] Found\x1b[39m: {url} : '{name}' v{ver}"
    },
    'aux': {
        'N\A': 'N\A',
        'ver': 'v0.4 beta'
    }
}


def check_yaml_structure(data):
    
    # Checking 'info' section
    if 'meta' not in data or not isinstance(data['meta'], dict):
        return {'status': False, 'msg': get_text['yaml_check']['metadata_missing']}
    if not data['meta'].get('version', ''):
        return {'status': False, 'msg': get_text['yaml_check']['metadata_version_missing']}
    

    # Checking 'request' section
    if 'request' in data:
        request_config = data['request']
        if not isinstance(request_config, dict):
            return {'status': False, 'msg': get_text['yaml_check']['request_config_format']}
        
        # Checking 'method' field
        if 'method' in request_config and request_config['method'].upper() not in ['GET', 'OPTIONS', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']:
            return {'status': False, 'msg': get_text['yaml_check']['unsupported_method'].format(method=request_config['method'])}
        
        # Checking 'post_data' for 'POST' method
        if request_config.get('method', '').upper() == 'POST' and 'post_data' not in request_config:
            return {'status': False, 'msg': get_text['yaml_check']['post_data_missing']}
        
        # Checking 'url' field format
        if 'url' in request_config and not request_config.get('url', '').startswith('/'):
            return {'status': False, 'msg': get_text['yaml_check']['url_path_incorrect']}



    # Checking 'versions' section
    if 'versions' not in data or not isinstance(data['versions'], list):
        return {'status': False, 'msg': get_text['yaml_check']['versions_missing']}
    else:
        for version in data['versions']:
            if not isinstance(version, dict): 
                return {'status': False, 'msg': get_text['yaml_check']['version_structure_incomplete']}

            elif 'body' in version:
                if 'name' not in version:
                    return {'status': False, 'msg': get_text['yaml_check']['missing_name']}
                elif 'match_string' not in version['body'] and 'match_regex' not in version['body']:
                    return {'status': False, 'msg': get_text['yaml_check']['missing_match_rules'].format(version_name=version['name'])}

    return {'status': True}

def read_file(file_path, type):
    try:
        with open(file_path, 'r') as file:
            if type == 'yaml_module':
                return yaml.safe_load(file)
            elif type == 'ip_list':
                urls = [line.strip() for line in file.readlines()]
                return urls
            else:
                return None
             
    except FileNotFoundError:
        return None

async def get_yamlTag(check_nameValue, getTag, yaml_file):

    instances = yaml_file.get(getTag)
    for yaml_name in instances:
        if yaml_name['name'] == check_nameValue:
            return yaml_name
    return False

async def fetch_responses(urls, yaml_serverModule, timeout, silent_mode):
    yaml_serverArgs = []
    if yaml_serverModule:
        yaml_serverArgs = [
            yaml_serverModule.get('method', 'GET'),
            yaml_serverModule.get('url', ''),
            yaml_serverModule.get('redirects', True),
            yaml_serverModule.get('expected_status', None),
            yaml_serverModule.get('post_data', None),
            yaml_serverModule.get('headers', None)
        ]


    fetch_tasks = [
        asyncio.create_task(
            perform_request(url, timeout, silent_mode, *yaml_serverArgs)
        ) for url in urls
    ]
    for completed_fetch_task in asyncio.as_completed(fetch_tasks):
        result = await completed_fetch_task
        if result:
            yield result

async def perform_request(url, timeout, silent_mode,  method='GET', yaml_dir='', follow_redirects=True, response_code=None, post_data=None, headers=None):
    raise_for_status = False

    if headers is None or headers.get('User-Agent') is None:
        headers = {'User-Agent': f"3eyes/{get_text['aux']['ver']}"}

    if yaml_dir: 
        url_format = urlparse(url)
        url = f'{url_format.scheme}://{url_format.netloc}{yaml_dir}'

    if isinstance(response_code, str) and response_code.lower() == 'ok':
        raise_for_status = True

    try:
        async with httpx.AsyncClient(
            verify=False, 
            timeout=timeout, 
            limits=httpx.Limits(max_connections=10),
            follow_redirects=follow_redirects
        ) as client:

            req = client.build_request(method.upper(), url, headers=headers, data=post_data)
            response = await client.send(req)

            if raise_for_status:
                response.raise_for_status()

            if response_code:
                if response.status_code == response_code or response_code.lower() == 'ok':
                    return {
                        'isOk': True,
                        'url': url,
                        'body': response.text
                    }
                elif not response.status_code == response_code:
                    if not silent_mode:
                        return {
                            'isOk': False,
                            'url': url,
                            'msg': get_text['info']['statusCode']
                        }
                    else:
                        return None

            else:
                return {
                    'isOk': True,
                    'url': url,
                    'body': response.text
                }

    # EAFP: It’s Easier to Ask for Forgiveness than Permission
    # https://docs.python.org/3/glossary.html#term-EAFP
    except httpx.TimeoutException:
        return {
            'isOk': False,
            'url': url,
            'msg': get_text['info']['timeOut']
        } if not silent_mode else None
    except httpx.HTTPStatusError: 
        print(1111) 
        return {
            'isOk': False,
            'url': url,
            'msg': get_text['info']['statusCode']
        } if not silent_mode else None
    except httpx.NetworkError:  
        return {
            'isOk': False,
            'url': url,
            'msg': get_text['info']['networkError']
        } if not silent_mode else None
    except httpx.UnsupportedProtocol:  
        return {
            'isOk': False,
            'url': url,
            'msg': get_text['info']['protocol']
        } if not silent_mode else None
    except httpx.HTTPError as e: #need more testing, sometimes it gives 'All connection attempts failed'
        return {
            'isOk': False,
            'url': url,
            'msg': f'HTTPError:{e}'
        } if not silent_mode else None
    except KeyboardInterrupt:
        pass # it will bubble up in 'asyncio.run(main())'

async def check_versions(response, versions, silent_mode, body_flag):

    if response['isOk']:
        response_body = response['body']

        versions = [versions] if isinstance(versions, dict) else versions  # Convert single version to list

        for version in versions:
            #print(version)
            match_string_yaml = version['body'].get('match_string')
            or_extract_yaml = version['body'].get('or_extract_regex')
            match_regex_yaml = version['body'].get('match_regex')
            extract_regex_yaml = version['body'].get('extract_regex')

            match_string = bool(match_string_yaml) and match_string_yaml in response_body
            match_regex = re.search(match_regex_yaml, response_body) if match_regex_yaml else None
            or_extract_match = re.search(or_extract_yaml, response_body) if or_extract_yaml else None
            extract_match = re.search(extract_regex_yaml, response_body)

            #print(match_string_yaml)
            if match_string or match_regex:
                version_number = None
                if extract_match:
                    version_number = extract_match.group(1)
                elif or_extract_match:
                    version_number = or_extract_match.group(1)
                elif match_regex and not extract_match and not or_extract_match:
                    version_number = match_regex.group(1)

                if version_number is not None:
                    return {
                        'isMatch': True,
                        'url': response['url'],
                        'name': version['name'],
                        'descr': version['body'].get('description', 'N/A'),
                        'ver': version_number,
                        'body' : response_body if body_flag else None
                    }
        if not silent_mode: 
            return {
                    'isMatch': False,
                    'url': response['url'],
                    'msg': get_text['info']['noMatch']
            }    

    elif not silent_mode:
        return {
                'isMatch': False,
                'url': response['url'],
                'msg': response['msg']
        } 

def print_bar(index, total, prt = None): 
    n_bar = 60
    progress = index / total
    sys.stdout.write('\r\x1b[2K') 
    if not int(100 * progress) == 100:
        if prt:
            sys.stdout.write(f'{prt}\n')
        sys.stdout.write(f"\x1b[96m[{'=' * int(n_bar * progress):{n_bar}s}] {int(100 * progress)}% [{index}/{total}]\x1b[39m")
    elif int(100 * progress) == 100 and prt: 
        sys.stdout.write(f'\x1b[2K{prt}')
    else:
        sys.stdout.write(f'\x1b[2K')
    sys.stdout.flush()

def print_execution_info(execution_time, current_url, succeeded_url, failed_url):
    success_percentage = (succeeded_url / current_url) * 100 if current_url != 0 else 0
    failure_rate = (failed_url / current_url) * 100 if current_url != 0 else 0

    print(f'\n\n\x1b[38;5;243m')
    print(f"Execution time: {execution_time:.2f} sec")
    print(f'Total: {current_url}')
    print(f'Succeed: {succeeded_url} ({success_percentage:.2f}%)')
    print(f'Fail: {failed_url} ({failure_rate:.2f}%)')
    print('\x1b[39m')
    
def print_starting_info(module_name):
    print(f'\x1b[38;5;243m>>> Starting with "{module_name}" module <<<\x1b[39m\n')
    

def _check_argsI(targets_file):
    try:
        with open(targets_file, 'r') as file:
            urls = [line.strip() for line in file.readlines() if line.strip()] # strip any empty lines or lines containing only whitespace
            return urls
    except FileNotFoundError:
        raise argparse.ArgumentTypeError(get_text['error']['fileNotFound'].format(value=targets_file))
    
def _check_argsM(module_name):
    try:
        module_path = os.path.join("modules", f"{module_name}.yaml")
        with open(module_path, 'r') as file:
            yaml_data = yaml.safe_load(file)
            if 'meta' in yaml_data and yaml_data['meta'].get('version'):
                return yaml_data
            else:
                raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(get_text['yaml_check']['metadata_version_missing'])
    except FileNotFoundError:
        raise argparse.ArgumentTypeError(get_text['error']['moduleFileNotFound'].format(value=module_name))

def _check_argsST(value):
    try:
        value = int(value)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(get_text['error']['invalidTimeOutFormat'].format(value=value))
      

def _check_argsSO(value):
    keys = re.findall(r'{(.*?)}', value)  # Extract keys within curly braces
    predefined_keys = ['url', 'ver', 'name', 'descr']

    for key in keys:
        if key not in predefined_keys:
            raise argparse.ArgumentTypeError(get_text['error']['invalidOutputFormat'].format(value=value))

    return value

    
async def final_print(result, final_url, current_url, total_urls, silent_mode, set_OutputString, check_versionsList):

    is_VerOk = False
    if check_versionsList is None or result['ver'] in check_versionsList:
        is_VerOk = True

    if silent_mode:
        if is_VerOk :
            if not set_OutputString:
                print(final_url)
            else:
                print(set_OutputString.format(url=final_url , name=result['name'], descr=result['descr'], ver=result['ver']))
            return {'is_VerOk' : True}
        else:
            return {'is_VerOk' : False }

    elif not set_OutputString and is_VerOk:
        default_output = get_text['info']['default_outputFormat'].format(url=final_url , name=result['name'], descr=result['descr'], ver=result['ver'])
        print_bar(current_url, total_urls, default_output)
        return {'is_VerOk' : True}

    elif set_OutputString and is_VerOk:
        custome_output = set_OutputString.format(url=final_url , name=result['name'], descr=result['descr'], ver=result['ver'])
        print_bar(current_url, total_urls, custome_output)
        return {'is_VerOk' : True}
    
    elif not is_VerOk:
        return {'is_VerOk' : False }



async def main():
    start_time = time.time()

    if platform.system() == 'Windows': 
        just_fix_windows_console() # colors for win 10 cmd

    parser = argparse.ArgumentParser(description=get_text['arg']['description'])
    parser.add_argument("-m", type=_check_argsM, required=True, help=get_text['arg']['module'])
    parser.add_argument("-i", type=_check_argsI, help=get_text['arg']['input'])
    parser.add_argument("-t", help=get_text['arg']['target'])
    parser.add_argument("-sm", help=get_text['arg']['set_moduleversions'])
    parser.add_argument("-so", type=_check_argsSO, help=get_text['arg']['set_outputString'])
    parser.add_argument("-st", type=_check_argsST, default=10, help=get_text['arg']['set_timeOut'])
    parser.add_argument("-cv", help=get_text['arg']['check_versionsList'])
    parser.add_argument("-v", action='store_true', help=get_text['arg']['verbose_mode'])
    parser.add_argument("-silent", action='store_true', help=get_text['arg']['silent_mode'])

    args = parser.parse_args()

    urls = []

    get_ModuleVersion = args.sm
    set_OutputString = args.so

    get_YamlFile = args.m
    get_Target = args.t
    get_YamlVersions = False

    verbose_mode = args.v
    silent_mode = args.silent

    check_versionsList = args.cv

    if not silent_mode:
        print(banner.format(ver=get_text['aux']['ver']))

    if sys.stdin.isatty():
        if get_Target and args.i:
            print(get_text['error']['noTarget'])
        elif get_Target: 
            urls.append(get_Target)
        elif args.i:
            urls = args.i
        else:
            print(get_text['error']['noTarget'])
    else:
        for line in sys.stdin:
            urls.append(line.strip())

    if not get_ModuleVersion: 
        get_YamlVersions = get_YamlFile.get('versions')
    else:
        specific_version = await get_yamlTag(get_ModuleVersion, 'versions', get_YamlFile)
        if not specific_version:
            print(get_text['error']['moduleVersionNotFound'].format(version_name=get_ModuleVersion))
        else:
            get_YamlVersions = specific_version


    if urls and get_YamlFile and get_YamlVersions:
            check_yaml = check_yaml_structure(get_YamlFile)

            if check_yaml['status']:

                total_urls = len(urls)
                succeeded_url = 0
                failed_url = 0
                current_url = 0
                
                print_starting_info(get_YamlFile["meta"].get("name", "unknown")) if not silent_mode else None

                async for request in fetch_responses(urls, get_YamlFile.get('request'), args.st, silent_mode): 
                    #print(request)
                    current_url += 1

                    if request['isOk']:
                        search_tasks = [check_versions(request, get_YamlVersions, silent_mode, False)]

                        for completed_task in asyncio.as_completed(search_tasks):
                            result = await completed_task

                            if result:
                                url_format = urlparse(result['url'])
                                final_url = f'{url_format.scheme}://{url_format.netloc}'

                                if result['isMatch']:

                                    final_result = await final_print(result, final_url, current_url, total_urls, silent_mode, set_OutputString, check_versionsList)
                                    
                                    if final_result['is_VerOk']: 
                                        succeeded_url += 1
                                    else:
                                        failed_url += 1
                                        if verbose_mode:
                                            print_bar(current_url, total_urls, get_text['info']['noVerMatch'].format(url=final_url) )

                                elif get_Target:
                                    failed_url += 1
                                    print(get_text['info']['targetNotFound'].format(msg=result['msg'],url=final_url))

                                elif verbose_mode:
                                    failed_url += 1
                                    print_bar(current_url, total_urls, get_text['info']['targetNotFound'].format(msg=result['msg'],url=final_url))
                                
                                elif not verbose_mode:
                                    failed_url += 1
                                    print_bar(current_url, total_urls)

                    elif not request['isOk']:
                        failed_url += 1
                        if get_Target:
                            print(get_text['info']['targetNotFound'].format(msg=request['msg'],url=request['url']))
                        if not verbose_mode: 
                            print_bar(current_url, total_urls)
                        elif verbose_mode:
                            print_bar(current_url, total_urls, get_text['info']['targetNotFound'].format(msg=request['msg'],url=request['url']))
                    
                if not silent_mode:
                    end_time = time.time()  # End the timer
                    execution_time = end_time - start_time
                    print_execution_info(execution_time, current_url, succeeded_url, failed_url)
            else:
                print(check_yaml['msg'])

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nKeyboard interrupt detected")
