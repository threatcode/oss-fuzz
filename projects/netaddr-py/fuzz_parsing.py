#!/usr/bin/python3
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import atheris

with atheris.instrument_imports():
    from netaddr import IPAddress, IPNetwork, IPRange, AddrFormatError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    s1 = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1024))
    s2 = fdp.ConsumeString(fdp.ConsumeIntInRange(0, 1024))
    try:
        IPAddress(s1)
        IPNetwork(s1)
        IPRange(s1,s2)
    except AddrFormatError as e:
        None
    except ValueError as e:
        msgs = [
            "is an invalid IP version",
            "netmasks or subnet"
        ]
        found = False
        for msg in msgs:
            if msg in str(e):
                found = True
        if not found:
            raise e


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
