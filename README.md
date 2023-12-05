# 3eyes Framework

3Eyes is a community based asynchronous web identification python framework, primarily designed to identify web instances and their versions using YAML-based fingerprinting. It offers two modes: normal, verbose, catering to different output preferences. The framework allows users to check specific versions, customize output formats, and can accept input from other applications.

## Features

- **Identification Modes:**
  - *Normal Mode:* Shows valid URLs only.
  - *Verbose Mode:* Displays all URLs, valid or invalid.

- **Examples:**

- Checking for a specific instance: 
```
python 3eyes.py -m grafana -t https://localhost -sm "Grafana Enterprise" 
```

- Checking for a specific version: 
```
python 3eyes.py -m grafana -t https://localhost -cv "7.4.0 7.4.1 7.4.2" 
```

- Setting the global output: 
```
python 3eyes.py -m grafana -t https://localhost -so "found {{url}} with {{name}} v{{ver}}"
```
**Note:** *valid arguments are {{url}}, {{name}}, {{descr}} and {{ver}}*

- Adding extra logic by executing the argument tags (representative by 'x.' at the start): 
```
python 3eyes.py -m grafana -t https://localhost -so "found {{url}} with host info {{x.getHostInfo}}"
```
- Utilizing the -i argument (for inputting a bulk file with targets) will result in the generation of a summary:
```
python 3eyes.py -m grafana -i url_examples.txt
```
Output:
```
(...)

[+] Percentages based on total URLs.
[-] Execution time: 3.2 sec
[-] Total:          96
[-] Succeed:         2 2.08%
    └─ Grafana OSS: 2.08%
        └─ 7.4.3:    1 1.04%
        └─ 8.4.6:    1 1.04%
[-] Fail:           94 97.92%
    └─ StatusCode:  84 87.5%
    └─ NoMatch:     10 10.42%
```

## Roadmap

The framework is in its early stages and actively seeking optimization for scalability and new functionalities. Key areas in development include:

- **Modularization:** Required to enhance scalability for future features.
- **Async Speed Optimization:** Enhancing asynchronous processing for improved performance.
- **Module Creation Facilitation:** Updating the framework to assist in creating identification modules.
- **CLI Enhancement:** Improving CLI aspects like color, text placement, and error messaging.

**Note:** The YAML module logic is currently in active development and isn't open to community contributions in these early stages.

## License

The project is available under the MIT License, allowing widespread use with attribution. See the `LICENSE` file for more details.

Contributions and feedback are welcome!
