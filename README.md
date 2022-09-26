# panther-classic-converter
Tool for converting classic Panther detections into the Config SDK format

```
usage: panther_classic_converter [-h] -f FILENAME [-a | --athena | --no-athena] [-o OUTPUT]

converts legacy detections to config sdk detections

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        YML filename to be converted
  -a, --athena, --no-athena
                        Datalake used by panther deployment. Used for scheduled queries.
  -o OUTPUT, --output OUTPUT
                        YML filename to be converted
```
