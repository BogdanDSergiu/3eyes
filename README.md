# 3Eyes Framework

3Eyes is an asynchronous web identification python framework, primarily designed to identify web instances and their versions using YAML-based fingerprinting. It offers three modes: normal, verbose, and silent, catering to different output preferences. The framework allows users to check specific versions, customize output formats, and can accept or pipe information to other applications.

## Features

- **Identification Modes:**
  - *Normal Mode:* Shows valid URLs only.
  - *Verbose Mode:* Displays all URLs, valid or invalid.
  - *Silent Mode:* Outputs only URLs, ideal for piping information.

- **Customizable Output:** Tailor the output using tags like `{url}`, `{name}`, `{ver}`, `{descr}`.

- **YAML Module Support:** Check specific or multiple versions specified by the user in YAML format.

## Roadmap

The framework is in its early stages and actively seeking optimization for scalability and new functionalities. Key areas in development include:

- **Modularization:** Urgently required to enhance scalability for future features.
- **Async Speed Optimization:** Enhancing asynchronous processing for improved performance.
- **Module Creation Facilitation:** Updating the framework to assist in creating identification modules.
- **CLI Enhancement:** Improving CLI aspects like color, text placement, and error messaging.

**Note:** The YAML module is currently in active development and isn't open to community contributions in these early stages.

## License

The project is available under the MIT License, allowing widespread use with attribution. See the `LICENSE` file for more details.

Contributions and feedback are welcome!