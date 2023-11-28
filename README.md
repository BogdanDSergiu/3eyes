3Eyes - Web Identification Framework

3Eyes is an asynchronous web identification framework designed for detecting and fingerprinting web applications. It offers three modes of operation:

    Normal Mode: Displays only valid URLs.
    Verbose Mode: Shows all URLs with additional details, irrespective of their validity.
    Silent Mode: Outputs only the URL, useful for piping information to other apps.

Features:

    YAML Module Support: Allows checking for specific versions or single versions specified by the user using a YAML-based module.
    Customizable Output: Tailor output with tags like {url}, {name}, {ver}, {descr}.

Early Development Stage:

This framework is in its early stages, prioritizing functionality over optimization. The YAML module's structure is subject to change and isn't currently open to community contributions.
Roadmap:

    Modularization: Urgent need for modularization to scale well with future features.
    CLI Enhancements: Improving CLI aspects, including text formatting, messages, and error handling.
    Performance Optimization: Enhancing asynchronous speed for improved efficiency.
    Framework Updates: Adding features to aid in creating identification modules.