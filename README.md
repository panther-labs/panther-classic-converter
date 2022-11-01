# panther-classic-converter
Tool for converting classic Panther detections into the Panther SDK format.

The converted rule serves as a good baseline and maintains existing functionality.

It is recommended that the generated filter be replaced with a composable list of filters to take advantage of the benefits of composable detections.

## Installation
```
pip install panther-classic-converter
```

## Usage

```
usage: panther_classic_converter [-h] [-a | --athena | --no-athena] [-o OUTPUT] filename

converts legacy detections to panther sdk detections

positional arguments:
  filename              YML filename to be converted

optional arguments:
  -h, --help            show this help message and exit
  -a, --athena, --no-athena
                        Datalake used by panther deployment. Used for scheduled queries.
  -o OUTPUT, --output OUTPUT
                        YML filename to be converted
```

## Example

```
panther_classic_converter brute_force_by_ip.yml -o converted_brute_force_by_ip.py
```

### Before
[brute_force_by_ip.yml](https://github.com/panther-labs/panther-classic-converter/blob/main/tests/testdata/brute_force_by_ip.yml)

[brute_force_by_ip.py](https://github.com/panther-labs/panther-classic-converter/blob/main/tests/testdata/brute_force_by_ip.py)

### After
[converted_brute_force_by_ip.py](https://github.com/panther-labs/panther-classic-converter/blob/main/tests/testdata/brute_force_by_ip_converted.py)

