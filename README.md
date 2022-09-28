# panther-classic-converter
Tool for converting classic Panther detections into the Config SDK format

## Installation
```
pip install panther-classic-converter
```

## Usage

```
usage: panther_classic_converter [-h] [-a | --athena | --no-athena] [-o OUTPUT] filename

converts legacy detections to config sdk detections

positional arguments:
  filename              YML filename to be converted

optional arguments:
  -h, --help            show this help message and exit
  -a, --athena, --no-athena
                        Datalake used by panther deployment. Used for scheduled queries.
  -o OUTPUT, --output OUTPUT
                        YML filename to be converted
```
