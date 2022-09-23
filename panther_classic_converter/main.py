# Copyright (C) 2022 Panther Labs Inc
#
# Panther Enterprise is licensed under the terms of a commercial license available from
# Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
# All use, distribution, and/or modification of this software, whether commercial or non-commercial,
# falls under the Panther Commercial License to the extent it is permitted.

import argparse

from converter.converter import convert_detection


def main():
    parser = argparse.ArgumentParser(description="converts legacy detections to config sdk detections")
    parser.add_argument('-f', '--filename', help="YML filename to be converted", required=True)
    parser.add_argument('-a', '--athena', help="Datalake used by panther deployment.  Used for scheduled queries.",
                        required=False, action=argparse.BooleanOptionalAction)

    args = vars(parser.parse_args())

    result = convert_detection(args['filename'], args['athena'])
    print(result)


if __name__ == "__main__":
    main()
