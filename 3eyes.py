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
from collections import defaultdict


banner = """
\x1b[38;5;69m      _______                         
     |   _   |.-----.--.--.-----.-----.
     |___|   ||  -__|  |  |  -__|__ --|
      _(__   || ____|___  |_____|_____|
     |:  |   |      |_____|           
     |::.. . |              {ver}        
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
        'set_outputString': "Set output presentation, can be use with extra logic with {x.[arg name]}",
        'set_moduleVersions': "Set specified versions for target checking.",
        'set_timeOut': "Set timeout specification for requests, default is 10s",
        'verbose_mode': "Outputs all URL(s), default is False",
        'serverCheck' : 'Check the server first, default is False',
        'moduleCheck' : 'Only check the yaml module without further execution, default is False '
    },
    'yaml_check' : {
        'metadata_missing': "\x1b[31m[!] Module Error\x1b[39m: The meta tag structure is incomplete or the version is missing", #+
        'metadata_version_missing': "\n\x1b[31m[!] Module Error\x1b[39m: The 'version' in meta tag is missing", #+
        'request_config_format': "\x1b[31m[!] Module Error\x1b[39m: The 'request' tag configuration is not in the correct format", #+
        'unsupported_method': "\x1b[31m[!] Module Error\x1b[39m: The request method '{method}' in the request configuration is not supported", #+
        'post_data_missing': "\x1b[31m[!] Module Error\x1b[39m: Post data is mandatory if the request method is POST", #+
        'url_path_incorrect' : "\x1b[31m[!] Module Error\x1b[39m: The 'url' in the request tag must start with a forward slash ('/')", #+
        'server_config_format' : "\x1b[31m[!] Module Error\x1b[39m: The 'server' tag configuration is not in the correct format",
        'server_body': "\x1b[31m[!] Module Error\x1b[39m: The 'body' section within 'server' tag is missing.",
        'server_match_string': "\x1b[31m[!] Module Error\x1b[39m: The 'match_string' is missing within 'body' of 'server'.",
        'versions_missing': "\x1b[31m[!] Module Error\x1b[39m: The version information is missing or improperly structured", #+
        'version_structure_incomplete': "\x1b[31m[!] Module Error\x1b[39m: The version structure is incomplete or missing essential elements", #+
        'missing_name': "\x1b[31m[!] Module Error\x1b[39m: The 'name' dose not exists within the version tag", #+
    },
    'error': {
        'fileNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: File '{value}' not found.\n",
        'yamlNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: Module name not found.\n",
        'moduleNotSet':'\x1b[31m[!] Input Error\x1b[39m: No module file provided', #
        'moduleFileNotFound' : "\n\n\x1b[31m[!] Input Error\x1b[39m: The module '{value}.yaml' was not found in the 'modules' folder.", #+
        'specific_InfoNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: '{name}' name was not found in '{in_TagName}' tag of the module", #+
        'moduleVersionNotFound': "\n\n\x1b[31m[!] Input Error\x1b[39m: Module '{version_name}' not found in configuration.",
        'invalidTimeOutFormat': "\n\n\x1b[31m[!] Input Error\x1b[39m: Invalid timeout value '{value}'", #+
        'invalidOutputFormat': "\n\n\x1b[31m[!] Input Error\x1b[39m: Invalid key(s) in output format '{value}'", #+
        'invalidTargetInput': '\x1b[31m[!] Input Error\x1b[39m: Please provide -t or -i to specify the input source.' #+

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
        'ver': 'v0.52 beta'
    }
}


async def check_yaml_structure(data):
    
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
        

    # Checking 'server' section
    if 'server' in data:
        server_config = data['server']
        if not isinstance(server_config, dict):
            return {'status': False, 'msg': get_text['yaml_check']['server_config_format']} 
        elif 'body' not in server_config:
            return {'status': False, 'msg': get_text['yaml_check']['server_body']}  
        elif not isinstance(server_config['body'], dict) or 'match_string' not in server_config['body']: #OR mach_regex
            return {'status': False, 'msg': get_text['yaml_check']['server_match_string']}   


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

    return {'status': True}


async def get_specificInfo(name, in_TagName, yaml_file):
    instances = yaml_file.get(in_TagName)
    if instances is not None:
        for yaml_name in instances:
            if yaml_name['name'] == name:
                return {'isOk' : True, 'getYaml' : yaml_name}
        print(get_text['error']['specific_InfoNotFound'].format(name=name, in_TagName=in_TagName))
        return {'isOk' : False} 
    print(get_text['error']['specific_InfoNotFound'].format(name=name, in_TagName=in_TagName))
    return {'isOk' : False} 

   

def _check_argsI(targets_file):
    try:
        with open(targets_file, 'r') as file:
            urls = [line.strip() for line in file.readlines() if return_validURL(line.strip())]
            return urls
    except FileNotFoundError:
        raise argparse.ArgumentTypeError(get_text['error']['fileNotFound'].format(value=targets_file))
    

def _check_argsST(value):
    try:
        value = int(value)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(get_text['error']['invalidTimeOutFormat'].format(value=value))


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
    # except yaml.YAMLError as exc:
    #     print(f"Error while parsing YAML file: {exc}")
    #     return None
    except FileNotFoundError:
        raise argparse.ArgumentTypeError(get_text['error']['moduleFileNotFound'].format(value=module_name))


def return_validURL(url):
    return url.strip() != "" and " " not in url

async def print_starting_info(module_name, banner):
    print(banner.format(ver=get_text['aux']['ver']))
    print(f'\x1b[38;5;243m>>> Starting with "{module_name.get("name", "unknown")}" module created by "{module_name.get("author", "unknown")}" <<<\x1b[39m\n')   


async def fetch_responses(urls, yaml_serverModule, timeout):
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
            perform_request(url, timeout, *yaml_serverArgs)
        ) for url in urls
    ]
    for completed_fetch_task in asyncio.as_completed(fetch_tasks):
        result = await completed_fetch_task
        if result:
            yield result

async def perform_request(url, timeout,  method='GET', yaml_dir='', follow_redirects=True, response_code=None, post_data=None, headers=None):
    raise_for_status = False
    normal_urlFormat = None
    timeout_profile = httpx.Timeout(timeout=timeout, read=14)

    if headers is None or headers.get('User-Agent') is None:
        headers = {'User-Agent': f"3eyes/{get_text['aux']['ver']}"}

    if yaml_dir: 
        url_format = urlparse(url)
        normal_urlFormat = f'{url_format.scheme}://{url_format.netloc}'
        url = f'{normal_urlFormat}{yaml_dir}'

    if isinstance(response_code, str) and response_code.lower() == 'ok':
        raise_for_status = True

    try:
        async with httpx.AsyncClient(
            verify=False, 
            timeout=timeout_profile, 
            follow_redirects=follow_redirects
        ) as client: # limits=httpx.Limits(max_connections=10),

            req = client.build_request(method.upper(), url, headers=headers, data=post_data)
            response = await client.send(req)

            response.raise_for_status() if raise_for_status else None

            if response_code:
                if response.status_code == response_code or response_code.lower() == 'ok':
                    return {'isOk': True,'url': normal_urlFormat,'body': response.text, 'headers': response.headers}
                
                elif not response.status_code == response_code:
                    return {'isOk': False, 'url': normal_urlFormat, 'msg': get_text['info']['statusCode']}

            else:
                return {'isOk': True,'url': normal_urlFormat,'body': response.text}

    # EAFP: It’s Easier to Ask for Forgiveness than Permission
    # https://docs.python.org/3/glossary.html#term-EAFP
    except httpx.TimeoutException:
        return {'isOk': False,'url': normal_urlFormat,'msg': get_text['info']['timeOut']}
    
    except httpx.HTTPStatusError:
        return {'isOk': False, 'url': normal_urlFormat, 'msg': get_text['info']['statusCode']}
    
    except httpx.NetworkError:  
        return {'isOk': False, 'url': normal_urlFormat, 'msg': get_text['info']['networkError']}
    
    except httpx.UnsupportedProtocol:  
        return {'isOk': False, 'url': normal_urlFormat, 'msg': get_text['info']['protocol']}
    
    except httpx.HTTPError as e: #need more testing, sometimes it gives 'All connection attempts failed'
        return {'isOk': False, 'url': normal_urlFormat, 'msg': f'HTTPError:{e}'}
    
    except KeyboardInterrupt:
        # print(.....)
        client.close() # it will bubble up in 'asyncio.run(main())'

async def print_bar(index, total, prt = None): 
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

# async def print_bar(index, total, prt=None):
#     n_bar = 60
#     progress = index / total

#     # Clear the current line
#     sys.stdout.write('\r\x1b[2K')

#     # If progress is not 100%, print the progress bar
#     if not int(100 * progress) == 100:
#         if prt:
#             sys.stdout.write(f'{prt}\n')
#         sys.stdout.write(f"\x1b[96m[{'=' * int(n_bar * progress):{n_bar}s}] {int(100 * progress)}% [{index}/{total}]\x1b[39m")

#     # If progress is 100% and prt is not None, print prt
#     elif int(100 * progress) == 100 and prt:
#         sys.stdout.write(f'\x1b[2K{prt}')

#     # If progress is not 100% and prt is None, clear the line
#     else:
#         sys.stdout.write(f'\x1b[2K')

#     sys.stdout.flush()

async def extract_any_regexHelper(extract_any_regex_yaml, response_body):
    if extract_any_regex_yaml:
        for regex in extract_any_regex_yaml:
            check_any_extractMatch = re.search(regex, response_body)
            if check_any_extractMatch:
                return check_any_extractMatch
    else:
        return None


async def check_versions(response, versions): #check_versions(request, args.so['result'])
        response_info = response['body']
        #print(response_info)
        versions = [versions] if isinstance(versions, dict) else versions  # Convert single version to list
        try:
            for version in versions:
                
                match_string_yaml = version['body'].get('match_string')
                match_regex_yaml = version['body'].get('match_regex')

                extract_regex_yaml = version['body'].get('extract_regex', None)
                extract_any_regex_yaml = version['body'].get('extract_any_regex', None)

                # Check if match_string or match_regex is in response_info
                match_string = bool(match_string_yaml) and match_string_yaml in response_info
                match_regex = re.search(match_regex_yaml, response_info) if match_regex_yaml else None

                # Extract version number using extract_regex or extract_any_regex
                extract_regex = re.search(extract_regex_yaml, response_info) if extract_regex_yaml else None
                any_extract_regex = await extract_any_regexHelper(extract_any_regex_yaml, response_info)

                #print(f'match_string : {match_string} | match_regex : {match_regex}, extract_regex : {extract_regex}')
                #print(f'extract_match : {extract_match} | any_extract_regex {any_extract_regex}')

                 # If match_string or match_regex is found, extract version number
                if match_string or match_regex:
                    version_number = None

                    if extract_regex is None and any_extract_regex is None: # if is only validating and not extracting
                        return {
                            'isMatch': True,
                            'url': response['url'],
                            'name': version['name'],
                            'descr': version.get('description', get_text['aux']['N\A']),
                            'ver': get_text['aux']['N\A']
                        }

                    elif extract_regex:
                        version_number = extract_regex.group(1)
                    elif match_regex:
                        version_number = match_regex.group(1)
                    elif any_extract_regex:
                        version_number = any_extract_regex.group(1)
                    # print(version_number)
                    # If version number is found, return success message
                    if version_number is not None:
                        return {
                            'isMatch': True,
                            'url': response['url'],
                            'name': version['name'],
                            'descr': version.get('description', get_text['aux']['N\A']),
                            'ver': version_number
                        }
            # If no match is found, return failure message
            return {
                'isMatch': False,
                'url': response['url'],
                'msg': get_text['info']['noMatch']
            }
            
        except TypeError as te: # TO-DO: rewrite it with return error and let it handle in the main(), update the get_Text[]
            print(f"Error in '{version['name']}': {te}")
           # return {'isMatch': False, 'msg': 'AppError'}


async def pre_check(request, yaml_file):

    if 'body' in  yaml_file['server']: # TO-DO: headers
        match_string_yaml = yaml_file['server']['body'].get('match_string', '')

        match_string = match_string_yaml in request['body']

        if match_string:
            return True
        else:
            return False



async def _check_argsSO(value, get_YamlFile):
    try:
        pattern = r'\{x\.(\w+)}'  # Define the regex pattern
        matches = re.findall(pattern, value)

        result = {}

        for match in matches:
            check_match = await get_specificInfo(match, 'arguments', get_YamlFile) # {'isOk' : True, 'getYaml' : yaml_name}
            if check_match['isOk']:
                new_value = value
                new_value = new_value.replace(f'{{x.{match}}}', '')  # Update value without the matched pattern
                extract_regex = check_match['getYaml']['body'].get('extract_regex')

                result[match] = [extract_regex] if extract_regex else ['N/A']
            else:
                return 'Error'

        if result:
            return {'string': value, 'have_extra': True, 'result': result}
        else:
            return {'string': value, 'have_extra': False}

    except KeyError:
        return 'Error'
    


async def extract_arg_regexHelper(result_dict, response_body):
    result = {}

    for arg_name, regex_value in result_dict.items():  
        for regex in regex_value:
            check_extract = re.search(regex, response_body)
            if check_extract:
                result[arg_name] = check_extract.group(1)  
            else:
                result[arg_name] = 'N/A'  

    return result



async def printTrue_basedOnMode(get_Target, result, index_url, total_urls, set_output = False , get_arg_result = False):

    string_output = get_text['info']['default_outputFormat']
    
    if set_output:
        if set_output['have_extra']:
            new_output = set_output['string']

            for name, value in get_arg_result.items():  # Use .items() to iterate over key-value pairs
                new_output = new_output.replace(f'{{x.{name}}}', value)
            string_output = new_output
        else:
            string_output = set_output['string']

    outputFormat = string_output.format(
        url=result['url'],
        name=result['name'],
        descr=result['descr'],
        ver=result['ver']
    )            
    
    if get_Target: 
        print(outputFormat)
    else:
        await print_bar(index_url, total_urls, outputFormat)
        

async def printFalse_basedOnMode(get_Target, verbose_mode, msg, url, index_url, total_urls):
    if get_Target:
        print(get_text['info']['targetNotFound'].format(msg=msg, url=url))

    elif not verbose_mode: 
        await print_bar(index_url, total_urls)

    else:
        await print_bar(index_url, total_urls, get_text['info']['targetNotFound'].format(msg=msg, url=url))

################## The resume ##################

def calculate_percentage(value, total):
    return (value / total) * 100 if total != 0 else 0

def get_max_length(dictionary):
    return max(len(key) for key in dictionary.keys())

def get_formatted_line(length, max_len, is_percentage=False):
    if is_percentage:
        return '{:<'+ str(length+4) +'} {:>'+ str(max_len+1) +'} {:>1}'
    else:
        return '{:<'+ str(length+4) +'} {:>'+ str(max_len+1) +'}'

def print_execution_info(execution_time, error_messages, successful_vers):
    failed_url = sum(error_messages.values())
    succeeded_url = sum(sum(version_counts.values()) for version_counts in successful_vers.values())

    index_url = failed_url + succeeded_url

    success_percentage = calculate_percentage(succeeded_url, index_url)
    failure_percentage = calculate_percentage(failed_url, index_url)

    max_len = len(str(index_url))

    max_key_length = get_max_length(successful_vers)
    adjusted_length = max_key_length + 3

    normal_line = get_formatted_line(adjusted_length, max_len)
    percent_line = get_formatted_line(adjusted_length, max_len, is_percentage=True)
    
    single_word = '{:<20}'

    # Calculate percentages for successful versions
    version_percentages = {}
    for version_name, version_counts in successful_vers.items():
        total_count = sum(version_counts.values())
        version_percentage = calculate_percentage(total_count, index_url)
        version_percentages[version_name] = version_percentage

    # Sort versions by percentage
    sorted_versions = sorted(version_percentages.items(), key=lambda x: x[1], reverse=True)

    # Print sorted versions
    if sorted_versions:
        print('\n\x1b[38;5;243m')
        print('[+] Percentages based on total URLs.')
        print(normal_line.format('[-] Execution time:', str(round(execution_time, 2)) + ' sec'))
        print(normal_line.format('[-] Total:', index_url))
        print(percent_line.format('[-] Succeed:', succeeded_url, str(round(success_percentage, 2)) + '%'))

        for version_name, version_percentage in sorted_versions:
            print(single_word.format(f"    └─ {version_name}: {round(version_percentage, 2)}%"))

            # Access counts for the current version from successful_vers
            version_counts = successful_vers[version_name]

            # Sort versions within each category based on counts or percentages
            sorted_versions_within_category = sorted(version_counts.items(), key=lambda x: x[1], reverse=True)

            for version, count in sorted_versions_within_category:
                version_percentage = calculate_percentage(count, index_url)
                print(percent_line.format(f"        └─ {version}:", count, f"{round(version_percentage, 2)}%"))

        print(percent_line.format('[-] Fail:', failed_url, str(round(failure_percentage, 2)) + '%'))

        if error_messages:
            for error_msg, count in error_messages.items():
                error_percentage = calculate_percentage(count, index_url)
                print(percent_line.format('    └─ ' + error_msg + ':', count, str(round(error_percentage, 2)) + '%'))

        print('\x1b[39m')

################## The resume end ###############


async def process_data(request, index_url, urls, args):
    noMatch_value = get_text['info']['noMatch']
    get_YamlFile = args.m
    get_Target = args.t

    verbose_mode = args.v

    total_urls = len(urls)

    if not request['isOk']:
        await printFalse_basedOnMode(get_Target, verbose_mode, request['msg'], request['url'], index_url, total_urls)
        return {'status':False, 'msg': request['msg']}

    # now the request['isOk'] is True, eg format: {'isOk': True, 'url': '....','body': '...', 'headers': '...'}

    if args.cs and 'server' in get_YamlFile:
        if not await pre_check(request, get_YamlFile):
            await printFalse_basedOnMode(get_Target, verbose_mode, noMatch_value, request['url'], index_url, total_urls)
            return {'status':False, 'msg': noMatch_value}


    search_tasks = [check_versions(request, args.sm or get_YamlFile['versions'])] 
    for completed_task in asyncio.as_completed(search_tasks):
        result = await completed_task
        
        if not result['isMatch']: #TO-DO: if a error in module, stop here
            await printFalse_basedOnMode(get_Target, verbose_mode, noMatch_value, result['url'], index_url, total_urls)
            return {'status':False, 'msg': noMatch_value}

        # now result['isMatch'] is True, eg format: {'isMatch': True, 'url': '...', 'name': '...', 'descr': '...', 'ver': '...'}

        if args.cv and not result['ver']:
            await printFalse_basedOnMode(get_Target, verbose_mode, 'NoVerMatch', result['url'], index_url, total_urls)
            return {'status':False, 'msg': 'NoVerMatch'}

        # now result['ver'] is ok

        if args.so: 
            res = False
            if args.so['have_extra']:
                res = await extract_arg_regexHelper(args.so['result'], request['body'])

            await printTrue_basedOnMode(get_Target, result, index_url, total_urls, args.so, res)
            return {'status' : True, 'msg': result['ver'], 'ver_name': result['name']}
            
        if not args.so:
            await printTrue_basedOnMode(get_Target, result, index_url, total_urls)
            return {'status' : True, 'msg': result['ver'], 'ver_name' : result['name']}


async def main(args, urls, start_time):

    index_urlNumber = 0
    get_YamlFile = args.m

    error_messages = defaultdict(int)
    successful_vers = {}

    await print_starting_info(get_YamlFile["meta"], banner)

    async for request in fetch_responses(urls, get_YamlFile.get('request'), args.st): 
        index_urlNumber += 1
        get_data = await process_data(request, index_urlNumber, urls, args)
        if get_data is not None and get_data['status']:
            # {'status' : True, 'msg': '....', 'ver_name': '.....'}
            successful_vers.setdefault(get_data['ver_name'], {})
            successful_vers[get_data['ver_name']][get_data['msg']] = successful_vers[get_data['ver_name']].get(get_data['msg'], 0) + 1

            # print(successful_vers) | {'Grafana OSS': {'7.4.3': 1}}
        elif get_data is None:
            error_messages['AppError'] += 1
        else:
            error_messages[get_data['msg']] += 1

    if not args.t: 
        end_time = time.time()
        exec_time = end_time - start_time
        print_execution_info(exec_time, error_messages, successful_vers)




async def init():
    start_time = time.time()

    if platform.system() == 'Windows': 
        just_fix_windows_console() # colors for win 10 cmd

    parser = argparse.ArgumentParser(description=get_text['arg']['description'])

    group1 = parser.add_argument_group("Set Option")
    group2 = parser.add_argument_group("Flags")

    parser.add_argument("-m", type=_check_argsM, required=True, help=get_text['arg']['module']) 
    parser.add_argument("-i", type=_check_argsI, help=get_text['arg']['input']) 
    parser.add_argument("-t", help=get_text['arg']['target'])
    parser.add_argument("-cv", help=get_text['arg']['check_versionsList']) # sv ?

    group1.add_argument("-sm", help=get_text['arg']['set_moduleVersions'])  
    group1.add_argument("-so", help=get_text['arg']['set_outputString']) 
    
    group1.add_argument("-st", type=_check_argsST, default=10, help=get_text['arg']['set_timeOut']) 

    group2.add_argument("-cs", action='store_true', help=get_text['arg']['serverCheck'])
    group2.add_argument("-cm", action='store_true', help=get_text['arg']['moduleCheck'])    
    group2.add_argument("-v", action='store_true', help=get_text['arg']['verbose_mode'])

    args = parser.parse_args()

    urls = []
    get_YamlFile = args.m

    if sys.stdin.isatty():
        # Terminal mode
        if args.t and args.i:
            print(get_text['error']['invalidTargetInput'])
        elif args.t:
            urls.append(args.t)
        elif args.i:
            urls = args.i
        elif not args.cm:
            print(get_text['error']['invalidTargetInput'])
    else: # TO-DO: need cli desgin
        #print(banner.format(ver=get_text['aux']['ver']))  
        print("Reading and waiting for stdin to finish ...")
        for line in sys.stdin:
            line = line.strip()
            if line == "":
                break  
            urls.append(line)


    if args.cm: # TO-DO: ADD STYLE AND ADD TO THE getText
        check_yaml = check_yaml_structure(get_YamlFile)
        if check_yaml['status']:
            print('module ok')
        else:
            print(check_yaml['msg'])       

    if args.sm: 
        get_versionModule = await get_specificInfo(args.sm, 'versions', get_YamlFile)
        if get_versionModule:
            args.sm = get_versionModule
        else:
            args.sm = 'Not Found'

    if args.so:
        args.so = await _check_argsSO(args.so, get_YamlFile)


    if urls and get_YamlFile and not args.sm == 'Not Found' and not args.so == 'Error':
        await main(args, urls, start_time)
    # else:
    #     print('no init() pass')



if __name__ == "__main__":
    try:
        asyncio.run(init())
    except KeyboardInterrupt:
        print("\n\nKeyboard interrupt detected")
