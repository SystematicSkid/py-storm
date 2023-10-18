# PyStorm
A Python module-based Hivestorm script for 2023.

Most of the scans and work it does is based off of the CIS Benchmarks for Ubuntu and Debian. You can find them here: https://www.cisecurity.org/cis-benchmarks/

This script contains very modularized 'scanners' which each scan common file paths on Unix systems for the day of the competition.
They all require Python3 to be installed on the target systems, so you may need to install that using the following command:
```bash
sudo apt install python3
```

## Usage
To use this script, you must first clone the repository to your local machine. You can do this by running the following command:
```bash
git clone https://github.com/SystematicSkid/py-storm.git
```
Then, you can run the script by running the following command:
```bash
python3 main.py
```

## Contributing
This was our last (and first for some) year doing Hivestorm, so we won't be updating this script anymore. However, if you want to contribute, feel free to make a pull request and we'll review it.

## License
This code is licensed under the GPLv3 license. See the LICENSE file for more information.