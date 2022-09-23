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
    parser.add_argument('-o', '--output', help="YML filename to be converted", required=False)

    args = vars(parser.parse_args())

    input_filename = args['filename']
    result = convert_detection(input_filename, args['athena'])

    output_filename = args.get('output', default_output_filename(input_filename))
    with open(output_filename, 'w') as output_file:
        output_file.write(result)


def default_output_filename(og_filename: str) -> str:
    return f'converted_{og_filename}'


if __name__ == "__main__":
    main()
