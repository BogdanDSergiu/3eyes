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
                return yaml_name
        print(get_text['error']['specific_InfoNotFound'].format(name=name, in_TagName=in_TagName))
        return False 
    print(get_text['error']['specific_InfoNotFound'].format(name=name, in_TagName=in_TagName))
    return False


async def _check_argsSO(value, get_YamlFile):
    try:
        pattern = r'\{x\.(\w+)}'  # Define the regex pattern
        matches = re.findall(pattern, value)

        for match in matches:
            check_match = await get_specificInfo(match, 'arguments', get_YamlFile)
            if check_match:
                new_string = value.replace(f'{{x.{match}}}', '')
                if new_string.format(url=True, ver=True, name=True, descr=True):
                    return {'string': value , 'name' : match, 'arg': check_match}
        return 'Error'
    
    except KeyError:
        print(3)
        return 'Error'


def _check_argsSO_BAK(value):
    try:
        value.format(url=True, ver=True, name=True, descr=True, arg=True)
        return value
    except KeyError:
        raise argparse.ArgumentTypeError(get_text['error']['invalidOutputFormat'].format(value=value))
    

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

def print_starting_info(module_name, banner):
    print(banner.format(ver=get_text['aux']['ver']))
    print(f'\x1b[38;5;243m>>> Starting with "{module_name.get("name", "unknown")}" module created by "{module_name.get("author", "unknown")}" <<<\x1b[39m\n')   


def print_execution_info(execution_time, index_url, succeeded_url, error_messages, successful_vers):
    failed_url = sum(error_messages.values())

    success_percentage = (succeeded_url / index_url) * 100 if index_url != 0 else 0
    failure_rate = (failed_url / index_url) * 100 if index_url != 0 else 0

    max_len = len(str(index_url))

    print('\n\x1b[38;5;243m')
    print('[+] Percentages based on total URLs.')
    print(f"[-] Execution time: {execution_time:.2f} sec")
    print(f'{"[-] Total:":<19}{index_url}')

    print(f'{"[-] Succeed:":<19}{succeeded_url} {success_percentage:.1f}%')
    if successful_vers:
        for version, count in successful_vers.items():
            version_percentage = (count / index_url) * 100 if index_url != 0 else 0
            print(f"{'    └─ ' + version + ':':<19}{count:>{max_len}} {version_percentage:.1f}%")

    print(f'{"[-] Fail:":<19}{failed_url} {failure_rate:.1f}%')
    if error_messages:
        for error_msg, count in error_messages.items():
            error_percentage = (count / index_url) * 100 if index_url != 0 else 0
            print(f"{'    └─ ' + error_msg + ':':<19}{count:>{max_len}} {error_percentage:.1f}%")
    print('\x1b[39m')


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
                    return {'isOk': True,'url': normal_urlFormat,'body': response.text}
                
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
        client.close() # it will bubble up in 'asyncio.run(main())'

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

async def extract_any_regexHelper(extract_any_regex_yaml, response_body):
    if extract_any_regex_yaml:
        for regex in extract_any_regex_yaml:
            check_any_extractMatch = re.search(regex, response_body)
            if check_any_extractMatch:
                return check_any_extractMatch
    else:
        return None


async def check_versions(response, versions):
        response_body = response['body']
        #print(response_body)
        versions = [versions] if isinstance(versions, dict) else versions  # Convert single version to list
        try:
            for version in versions:
                
                match_string_yaml = version['body'].get('match_string')
                match_regex_yaml = version['body'].get('match_regex')

                extract_regex_yaml = version['body'].get('extract_regex', None)
                extract_any_regex_yaml = version['body'].get('extract_any_regex', None)


                match_string = bool(match_string_yaml) and match_string_yaml in response_body
                match_regex = re.search(match_regex_yaml, response_body) if match_regex_yaml else None

                extract_regex = re.search(extract_regex_yaml, response_body) if extract_regex_yaml else None
                any_extract_regex = await extract_any_regexHelper(extract_any_regex_yaml, response_body)

                #print(f'match_string : {match_string} | match_regex : {match_regex}, extract_regex : {extract_regex}')
                #print(f'extract_match : {extract_match} | any_extract_regex {any_extract_regex}')

                #print(f'match_string_yaml: {match_string_yaml} | match_regex_yaml: {match_regex_yaml}')

                if match_string_yaml is None and match_regex_yaml is None: # if in the arguments tag
                    if extract_regex:
                        return {'haveArg': True,'result': extract_regex.group(1)}
                    else:
                        return {'haveArg': False}
                    
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
#                    print(version_number)
                    if version_number is not None:
                        return {
                            'isMatch': True,
                            'url': response['url'],
                            'name': version['name'],
                            'descr': version.get('description', get_text['aux']['N\A']),
                            'ver': version_number
                        }

            return {
                'isMatch': False,
                'url': response['url'],
                'msg': get_text['info']['noMatch']
            }
            
        except TypeError as te: # TO-DO: rewrite it with return error and let it handle in the main(), update the get_Text[]
            if str(te) == "unhashable type: 'list'":
                print(f"Error in '{version['name']}' config: a tag is threated like a list, but it is not!")
            else:
                print(f"Error in '{version['name']}': {te}")


async def pre_check(request, yaml_file):

    if 'body' in  yaml_file['server']: # TO-DO: headers
        match_string_yaml = yaml_file['server']['body'].get('match_string', '')

        match_string = match_string_yaml in request['body']

        if match_string:
            return True
        else:
            return False


async def printTrue_basedOnMode(get_Target, result, index_url, total_urls, set_output = 'N/A', get_arg_result = 'N/A'):

    #set_output = {'string': value , 'name' : match, 'arg': check_match}

    default_outputFormat = None

    if not set_output == 'N/A':
        pattern = r'\{x\.(\w+)}'  # Define the regex pattern
        matches = re.findall(pattern, set_output['string'])

        if matches:
            new_output = set_output['string'].replace(f'{{x.{set_output["name"]}}}', get_arg_result)
            #print(new_output)
            default_outputFormat = new_output.format(url=result['url'] , name=result['name'], descr=result['descr'], ver=result['ver'])
        else:
            default_outputFormat = get_text['info']['default_outputFormat'].format(url=result['url'] , name=result['name'], ver=result['ver'])

    # PIPE MODE TEST

    if get_Target: 
        print(default_outputFormat)
    else:
        print_bar(index_url, total_urls, default_outputFormat)
        


async def printFalse_basedOnMode(get_Target, verbose_mode, msg, url, index_url, total_urls):
    if get_Target:
        print(get_text['info']['targetNotFound'].format(msg=msg, url=url))

    elif not verbose_mode: 
        print_bar(index_url, total_urls)

    else:
        print_bar(index_url, total_urls, get_text['info']['targetNotFound'].format(msg=msg, url=url))




async def main(args, urls, start_time):
    print('breakpoint4')

    noMatch_value = get_text['info']['noMatch']
    get_YamlFile = args.m
    get_Target = args.t

    verbose_mode = args.v

#    set_OutputFormat = args.so['string']
#    set_Arguments = args.so['arg']  

    total_urls = len(urls)
    succeeded_url = 0
    index_url = 0
    error_messages = defaultdict(int)
    successful_vers = defaultdict(int)

    print_starting_info(get_YamlFile["meta"], banner)

    async for request in fetch_responses(urls, get_YamlFile.get('request'), args.st): 
        #print(request)
        index_url += 1

        if request['isOk']:  # eg: {'isOk': True,'url': url,'body': '...'}

            preCheck_value = None

            if args.cs and 'server' in get_YamlFile:
                preCheck_isOk = await pre_check(request, get_YamlFile)
                if not preCheck_isOk:
                    preCheck_value = False
                    error_messages[noMatch_value] += 1
                    await printFalse_basedOnMode(get_Target, verbose_mode, noMatch_value, request['url'], index_url, total_urls)

            if preCheck_value is None:
                search_tasks = [check_versions(request, args.sm or get_YamlFile['versions'])] 

                for completed_task in asyncio.as_completed(search_tasks):
                    result = await completed_task

                    if result['isMatch']: # eg: {'isMatch': True, 'url': '...', 'name': '...', 'descr': '...', 'ver': '...'}
                        checkVersion_value = False if args.cv and not result['ver'] in args.cv else None

                        if checkVersion_value is None and args.so:
                            res = await check_versions(request, args.so['arg'])
                            if res['haveArg']: # {'haveArg': True,'result': '...'}
                                await printTrue_basedOnMode(get_Target, result, index_url, total_urls, args.so, res['result'])
                                successful_vers[result['ver']] += 1

                        elif checkVersion_value is None and not args.so:
                            succeeded_url += 1
                            await printTrue_basedOnMode(get_Target, result, index_url, total_urls)
                            successful_vers[result['ver']] += 1

                        else:  # no checkVersion_value
                            error_messages['NoVerMatch'] += 1
                            await printFalse_basedOnMode(get_Target, verbose_mode, 'NoVerMatch', result['url'], index_url, total_urls)


                    elif not result['isMatch']:
                        error_messages[result['msg']] += 1
                        await printFalse_basedOnMode(get_Target, verbose_mode, noMatch_value, result['url'], index_url, total_urls)


        elif not request['isOk']: # eg: {'isOk': False,'url': '...', 'msg': '...'}

            error_messages[request['msg']] += 1
            await printFalse_basedOnMode(get_Target, verbose_mode, request['msg'], request['url'], index_url, total_urls)
    
    if not args.t:
        end_time = time.time()  # End the timer
        execution_time = end_time - start_time
        print_execution_info(execution_time, index_url, succeeded_url, error_messages, successful_vers)




async def init():
    print('breakpoint2')
    start_time = time.time()

    if platform.system() == 'Windows': 
        just_fix_windows_console() # colors for win 10 cmd
    print('breakpoint3')

    parser = argparse.ArgumentParser(description=get_text['arg']['description'])

    group1 = parser.add_argument_group("Set Option")
    group2 = parser.add_argument_group("Flags")

    parser.add_argument("-m", type=_check_argsM, required=True, help=get_text['arg']['module']) 
    parser.add_argument("-i", type=_check_argsI, help=get_text['arg']['input']) 
    parser.add_argument("-t", help=get_text['arg']['target'])
    parser.add_argument("-cv", help=get_text['arg']['check_versionsList']) # sv ?

    group1.add_argument("-sm", help=get_text['arg']['set_moduleVersions'])  
    #group1.add_argument("-so", type=_check_argsSO, help=get_text['arg']['set_outputString']) 
    group1.add_argument("-so", help=get_text['arg']['set_outputString']) 
    
    group1.add_argument("-st", type=_check_argsST, default=10, help=get_text['arg']['set_timeOut']) 

    group2.add_argument("-cs", action='store_true', help=get_text['arg']['serverCheck'])
    group2.add_argument("-cm", action='store_true', help=get_text['arg']['moduleCheck'])    
    group2.add_argument("-v", action='store_true', help=get_text['arg']['verbose_mode'])


    args = parser.parse_args()

    urls = []
    get_YamlFile = args.m
    get_OutputFormat = None


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

    # if args.sa: 
    #     get_argumentModule = await get_specificInfo(args.sa, 'arguments', get_YamlFile)
    #     if get_argumentModule:
    #         args.sa = get_argumentModule
    #     else:
    #         args.sa = 'Not Found'

    if args.so:
        args.so = await _check_argsSO(args.so, get_YamlFile)


    if urls and get_YamlFile and not args.sm == 'Not Found' and not args.so == 'Error':
        await main(args, urls, start_time)



if __name__ == "__main__":
    print('breakpoint1')
    try:
        asyncio.run(init())
    except KeyboardInterrupt:
        print("\n\nKeyboard interrupt detected")
