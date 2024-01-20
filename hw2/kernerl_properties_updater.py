#!/usr/bin/env python

import argparse
import os.path
import json


if __name__ == '__main__':
    desc = '''Insert macro definition configured linux kernel for VSCode configuration.'''

    arg_parser = argparse.ArgumentParser(description=desc)
    arg_parser.add_argument('-k', '--kernel-path',
                            action='store',
                            required=True,
                            help='Specify kernel path. Need configured properly')
    arg_parser.add_argument('-f', '--file',
                            action='store',
                            required=True,
                            help='c_cpp_properties.json for VSCode')

    args = arg_parser.parse_args()

    autoconf_path = os.path.join(
        args.kernel_path, "include/generated/autoconf.h")

    if not os.path.exists(args.kernel_path) or \
            not os.path.exists(args.file):
        print('Check files')
        exit(1)

    defines = []
    with open(autoconf_path) as fp:
        for raw_line in fp.readlines():
            if not raw_line.startswith('#define'):
                continue

            slines = raw_line.split()
            k = slines[1]
            v = slines[2]

            defines.append('{}={}'.format(k, v))

    with open(args.file) as fp:
        properties = json.load(fp)

        for conf in properties['configurations']:
            if 'defines' in conf.keys():
                conf['defines'].extend(defines)

    with open(args.file, 'w') as fp:
        json.dump(properties, fp, indent=4)

    print('Added {} macros'.format(len(defines)))