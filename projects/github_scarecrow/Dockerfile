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
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN pip3 install requests
RUN git clone --depth 1 https://github.com/Alan32Liu/github-scarecrow.git $SRC/github-scarecrow
WORKDIR $SRC/github-scarecrow
RUN git clone --depth 1 https://github.com/threatcode/oss-fuzz
RUN cd oss-fuzz/infra/experimental/SystemSan && make
COPY shell_injection_poc_fuzzer.py fakelib.py build.sh $SRC/
